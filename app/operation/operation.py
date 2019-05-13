import asyncio
import logging
import inspect
import functools
import ssl
import threading
import time
import random
from collections import defaultdict
from typing import List, Type, Callable, Union, Dict, Optional
import traceback
import http.server
import socketserver
import mongoengine

from mongoengine import ListField, ReferenceField
from bson.objectid import ObjectId
from plugins.adversary.app.utility.general import get_simulated_domain_data

from plugins.adversary.app.operation.operation_obj import InterfaceWrapper, OperationWrapper
from plugins.adversary.app.operation.operation_script import ScriptContext
from plugins.adversary.app.engine.objects import Rat, ObservedUser, ObservedDomain, ObservedFile, ObservedCredential, \
    ObservedHost, ObservedShare, ObservedSchtask, ObservedTimeDelta, ObservedRat, Operation, ExtrovirtsDocument, \
    CodedStep, ObservedPersistence, ObservedService, ObservedRegKey, Host, AttackTechnique, ObservedProcess, \
    ObservedDevice, JobException, Trashed, ErrorLog, ObservedOSVersion, Setting

from plugins.adversary.app import event_logging
from plugins.adversary.app.logic import planner, logic
from plugins.adversary.app.operation.step import OPCredential, OPDomain, OPRat, OPFile, OPHost, OPSchtask, OPShare, OPTimeDelta, OPUser, \
    OPVar, \
    Step, Keyword, OPPersistence, OPService, OPRegKey, OPProcess, OPTrashed, OPOSVersion, OPDevice
from plugins.adversary.app import util
from plugins.adversary.app.commands import parsers
from plugins.adversary.app.commands import errors
from plugins.adversary.app.util import CaseException
from plugins.adversary.app.adversary import adversary
from plugins.adversary.app.operation.operation_errors import StepParseError, RatDisconnectedError, InvalidTimeoutExceptionError, \
    RatCallbackTimeoutError
from plugins.adversary.app.operation.cleanup import Cleaner
from plugins.adversary.app.steps import all_steps


try:
    from submodules.clips.app.logic.clips_logic import CLIPSContext as LogicContext
except ImportError:
    logging.warning("Couldn't find clips module. Falling back to slower pyDatalog")
    from plugins.adversary.app.logic.pydatalog_logic import DatalogContext as LogicContext

_database_objs = {OPUser: ObservedUser,
                  OPHost: ObservedHost,
                  OPDomain: ObservedDomain,
                  OPCredential: ObservedCredential,
                  OPFile: ObservedFile,
                  OPShare: ObservedShare,
                  OPSchtask: ObservedSchtask,
                  OPTimeDelta: ObservedTimeDelta,
                  OPRat: ObservedRat,
                  OPPersistence: ObservedPersistence,
                  OPService: ObservedService,
                  OPRegKey: ObservedRegKey,
                  OPDevice: ObservedDevice,
                  OPProcess: ObservedProcess,
                  OPTrashed: Trashed,
                  OPOSVersion: ObservedOSVersion}

_knowns = {ObservedUser: "known_users",
           ObservedHost: "known_hosts",
           ObservedDevice: "known_devices",
           ObservedDomain: "known_domains",
           ObservedCredential: "known_credentials",
           ObservedFile: "known_files",
           ObservedShare: "known_shares",
           ObservedSchtask: "known_schtasks",
           ObservedTimeDelta: "known_timedeltas",
           ObservedRat: "known_rats",
           ObservedPersistence: "known_persistence",
           ObservedService: "known_services",
           ObservedRegKey: "known_registry_keys",
           ObservedProcess: "known_processes",
           ErrorLog: "clean_log",
           Trashed: "known_trashed",
           ObservedOSVersion: "known_os_versions"}

_database_reference_fields = defaultdict(list)
for db_class in _database_objs.values():
    for field_name, field_value in db_class._fields.items():
        if isinstance(field_value, ReferenceField):
            _database_reference_fields[field_value.document_type].append((db_class, "field", field_name))
        elif isinstance(field_value, ListField) and isinstance(field_value.field, ReferenceField):
            _database_reference_fields[field_value.field.document_type].append((db_class, "list", field_name))

_inverse_database_objs = {v: k for k, v in _database_objs.items()}


class DBAction(object):
    """
    This class provides a wrapper for actions performed during an operation
    """

    def __init__(self, operation):
        self.operation = operation
        self.local_copy = {(x.name, *x.parameters) for x in self.operation.performed_actions}

    def append(self, item):
        self.operation.modify(push__performed_actions={"name": item[0], "parameters": item[1:]})
        self.local_copy.add(item)

    def pop(self):
        i = self.operation.modify(pop__performed_actions=1)
        self.local_copy.remove((i.name, *i.parameters))

    def __contains__(self, item):
        return item in self.local_copy

    def __getitem__(self, item):
        i = self.operation.performed_actions[item]
        return (i.name, *i.parameters)


class RatSubscriber(object):
    """
    This class will emit notifications about Rat connections and disconnections by subscribing to updates on the
    database collection
    """

    def __init__(self, hosts: List[Host], connect_cb: Callable[[ObjectId], None],
                 disconnect_cb: Callable[[ObjectId], None]):
        """
        Create a new subscriber

        Args:
            hosts: The hosts that we want to be notified about rat changes
            connect_cb: A callback for rat connection events
            disconnect_cb: A callback for rat disconnected events
        """
        self.connect_cb = connect_cb
        self.disconnect_cb = disconnect_cb
        self.active_task = None
        self.host_ids = [x.id for x in hosts]

    def __enter__(self):
        self.start()

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.stop()

    def start(self) -> None:
        """
        Starts looking for new rat events by creating a new asyncio task.
        Returns:
            None

        """
        self.active_task = asyncio.ensure_future(self._run())

    async def _run(self):
        inactive = set()
        active = set()
        [inactive.add(r) for r in Rat.existing_ids(dict(active=False))]
        while True:
            for rat in Rat.objects().as_pymongo().filter(id__nin=inactive):
                if 'active' not in rat:
                    continue
                if not rat['active']:
                    if rat['_id'] in active:
                        active.remove(rat['_id'])
                    inactive.add(rat['_id'])
                    self.disconnect_cb(rat['_id'])
                elif rat['_id'] not in active and rat['active']:
                    active.add(rat['_id'])
                    self.connect_cb(rat)
            await asyncio.sleep(2)

    def stop(self):
        """
        Stops the subscriber from running.
        Returns:
            None
        """
        if self.active_task:
            self.active_task.cancel()


class ServerOperation(object):
    """This manages running an operation
    """

    def __init__(self, con, operation: Operation, op_svc):
        """
        This is an object that manages running an operation

        Args:
            operation: The operation object that will be run
        """
        self.con = con
        self.logger = logging
        self._operation = operation
        self._steps = {step.__name__: step for step in Step.__subclasses__() if step.__name__ in operation.steps}
        self.performed_action = DBAction(operation)
        self._interface = InterfaceWrapper(operation)
        self.local_mapping = {}
        self.recursion_limit = Setting.objects.first().recursion_limit
        self.planner_depth = Setting.objects.first().planner_depth

        self._planner = planner.PlannerContext(LogicContext(), self.recursion_limit,
                                               performed_actions=self.performed_action,
                                               logger=self.logger)
        self.adversary_profile = adversary.AdversaryProfile(self._operation.adversary)
        self._wrapper = OperationWrapper(self, self._interface)
        self._cleaner = Cleaner(self, self._interface)
        self.operation_db = OperationDB(self._operation, self.logger)
        self._rat_waiters = []
        self._exfil_server = None
        self.bsf_emitter = event_logging.BSFEmitter(self._operation.log)
        self.op_svc = op_svc

    def rat_connected(self, rat_dict: Dict) -> None:
        """
        This function is called when a rat connects. It can handle repeat calls for the same rat

        Args:
            rat_dict: The dictionary of info for a connected rat

        Returns:
            Nothing
        """
        self.logger.info('Rat callback: {}'.format(rat_dict['_id']))
        ob_rat = self.pair_rat(rat_dict)

        # push any waiters onto queues
        for queue in self._rat_waiters:
            queue.put_nowait(ob_rat)

    def rat_disconnected(self, rat_id: ObjectId) -> None:
        """
        This function is called when a rat disconnects. It can handle repeat calls for the same rat

        Args:
            rat_id: The id of the disconnected rat

        Returns:
            Nothing
        """
        # make sure this is a rat we are interested in
        # refresh the object from the database
        self._operation.reload()
        for x in self._operation.rat_iv_map:
            if not x.rat.active and x.rat.id == rat_id and x.observed_rat in self._operation.known_rats:
                self.logger.info('Rat disconnect: {}'.format(rat_id))
                # move rat to non-existent category
                self._operation.modify(pull__known_rats=x.observed_rat)
                self._operation.modify(push__nonexistent_rats=x.observed_rat)

    @staticmethod
    def initialize_planner(planner_context: planner.PlannerContext, steps):
        planner_context = planner_context

        # load the actions into the planner
        for step in steps:
            coded_step = CodedStep.objects.get(name=step.__name__)
            action = logic.Action.load_from_database(coded_step, step)
            planner_context.add_action(action)

        # load types into the planner
        for obj in _database_objs:
            primary = obj != OPShare
            planner_context.define_type(obj.__name__, primary=primary)

    async def loop(self):
        """
        This function runs the operation. It will return only when the operation is ended

        Returns:
            Nothing
        """
        self.logger.info('Starting operation')
        self._exfil_server = [self.create_exfil_server(self.adversary_profile.get_exfil_port(),
                                                       self.adversary_profile.get_exfil_method()), False]
        self.initialize_planner(self._planner, self._steps.values())

        # when first booting up, blacklist all existing rats
        if self._operation.status == 'start':
            for iv in Rat.objects:
                self._operation.modify(push__ignored_rats=iv)
            self.bsf_emitter.start_operation()
        # Create an exfil server thread if necessary
        if "ExfilAdversaryProfile" in self._steps:
            self.logger.info("Activate exfil server")
            threading.Thread(target=self._exfil_server[0].serve_forever).start()
            self._exfil_server[1] = True

        # subscribe to rat updates
        with RatSubscriber(self._operation.network.hosts, self.rat_connected, self.rat_disconnected):
            # check once for disconnected rats that we missed before subscribing
            for x in self._operation.rat_iv_map:
                if not x.rat.active:
                    if x.observed_rat in self._operation.known_rats:
                        rat_id = x._data['rat'].id
                        self.rat_disconnected(rat_id)

            # check once for connected rats that we missed before subscribing
            for rat in Rat.objects:
                if rat not in self._operation.ignored_rats and rat.active:
                    found = False
                    for x in self._operation.rat_iv_map:
                        if x.rat.id == rat.id:
                            found = True
                            break
                    if not found:
                        self.rat_connected(rat.to_dict())
            await self.op_svc.run_operation(str(self._operation.id))

            async def job_delay():
                """
                This function attempts to delay an operation

                Returns:
                    Nothing
                """
                op_handle = self._interface.operation
                if op_handle.delay != 0 or op_handle.jitter != 0:
                    wait_time = op_handle.delay + random.uniform(-1 * op_handle.jitter, op_handle.jitter)
                    if wait_time < 0:
                        wait_time = op_handle.delay
                    await asyncio.sleep(wait_time / 1000)

            while True:
                if self._operation.stop_requested and self._operation.status not in ("cleanup", "complete"):
                    self._operation.modify(status="cleanup", reason="Stop was requested")
                if self._operation.status == 'start':
                    self._operation.modify(start_time=util.tz_utcnow())
                    self._operation.modify(status='bootstrapping')
                elif self._operation.status == 'bootstrapping':
                    try:
                        await self.bootstrap_commander()
                        self._operation.reload()
                        self._operation.modify(status="started")
                    except JobException as e:
                        self.logger.warning("Error on bootstrap: {}".format(e.args))
                        self._operation.modify(status="cleanup", reason="Error on bootstrap: {}".format(e.args))
                elif self._operation.status == 'started':
                    if self._operation.script:
                        reason = self.execute_script()
                        self._operation.modify(status="cleanup", reason=reason)
                    else:
                        step = await self._perform_next_step(self._planner)
                        if step is None:
                            self._operation.modify(status="cleanup", reason="No more plans")
                elif self._operation.status == "cleanup":
                    self.bsf_emitter.done()
                    self._operation.modify(status_state='')
                    if self._operation.perform_cleanup:
                        await self.cleanup()
                    self._operation.modify(status='complete', end_time=util.tz_utcnow())
                elif self._operation.status == "complete":
                    break
                else:
                    raise CaseException
                cancel = await self.op_svc.check_status(str(self._operation.id))
                if cancel and self._operation.status != "complete":
                    self._operation.modify(status="cleanup", reason="Cancel Requested")
                await job_delay()

        if self._exfil_server[1] is True:
            self._exfil_server[0].shutdown()
        self._exfil_server[0].server_close()

        self.logger.info("Operation complete: {}".format(self._operation.reason))
        self._planner.close()

    def execute_script(self) -> str:
        p = planner.PlannerContext
        sc = ScriptContext([p], self, all_steps, LogicContext)
        try:
            sc.run(self._operation.script)
        except Exception:
            self.logger.error('There was a problem executing the planner script: {}'.format(traceback.format_exc()))
            return "There was an error in the script"

        return "Script finished"

    async def cleanup(self):
        """
        This function handles cleanup. It should only run after all possible steps in the operation have been run.

        Returns:
            Nothing
        """

        def deref_id(obj_id):
            while obj_id in self._operation.object_references:
                obj_id = self._operation.object_references[obj_id]

            # find this object
            found_param = None
            for db_class in _database_objs.values():
                try:
                    found_param = db_class.objects.with_id(obj_id)
                except mongoengine.errors.ValidationError:
                    pass
                if found_param:
                    break
            if not found_param:
                raise Exception("Could not find {} in the database during cleanup".format(obj_id))
            return found_param

        try:
            # cleanup all rats automatically
            for mapping in self._operation.rat_iv_map:
                if mapping.observed_rat in self._operation.known_rats:
                    if mapping.rat.active:
                        await self._cleaner.delete(mapping.observed_rat)
                    self._operation.modify(pull__known_rats=mapping.observed_rat)
                    self._operation.modify(push__nonexistent_rats=mapping.observed_rat)

            # double check that the initial rat is dead (fixes occasional hang)
            if self._operation.start_type == "bootstrap":
                for entry in Rat.objects(active=True, executable=self._operation.start_path):
                    await self._cleaner.delete(entry)

            if self._operation.start_rat is not None:
                if self._operation.start_rat.active:
                    await self._cleaner.delete(self._operation.start_rat)
            # if bootstrapped, delete the starting rat's file
            if self._operation.start_type == "bootstrap":
                # find the right file
                try:
                    observed_host = self.operation_db.find_one(OPHost, {'fqdn': self._operation.start_host.fqdn})
                    file = self.operation_db.find_one(OPFile,
                                                      {'host': observed_host, 'path': self._operation.start_path})
                    await self._cleaner.delete(file)
                except IndexError:
                    # we get here if the host or file was never added to the database
                    pass
        except Exception as e:
            self.logger.warning('Encountered unexpected error cleaning up rats. If this was a simulated operation, ignore.')

        # cleanup processes
        start_index = self._operation.cleanup_index
        skips = {}
        current_set = 0
        try:
            for i, step_obj in enumerate(reversed(self._operation.performed_steps[start_index:])):
                current_set = i
                steps = {step.__name__: step for step in all_steps}
                step = steps.get(step_obj.name)
                sig = inspect.signature(step.cleanup)
                args = []

                for param_name in sig.parameters:
                    if param_name == 'cleaner':
                        args.append(self._cleaner)
                    else:
                        try:
                            param = step_obj.params[param_name]

                            # see if this has been renamed
                            if isinstance(param, list):
                                param = [deref_id(x) for x in param]
                            else:
                                param = deref_id(param)
                            args.append(param)
                        except KeyError:
                            raise Exception(
                                "Unspecified argument '{}' in cleanup function for '{}'".format(param_name,
                                                                                                step.__name__))

                valid = False
                if step.__name__ in skips:
                    if skips[step.__name__] != args:
                        valid = True
                else:
                    valid = True
                if valid:
                    self.logger.info("Cleanup triggered for {}({})".format(step.__name__, args))
                    await step.cleanup(*args)
                    skips[step.__name__] = args
                self._operation.modify(cleanup_index=i + start_index + 1)
            pass
        except Exception as e:
            self.logger.error('Encountered unexpected error cleaning up step')
            traceback.print_exc()
            self._operation.modify(cleanup_index=current_set + start_index + 1)

    async def bootstrap_commander(self) -> ObservedRat:
        """
        This function connects the starting rat to an operation during its setup.

        Returns:
            ObservedRat: The associated ObservedRat object for the starting rat
        """
        host = self._operation.start_host
        observed_host = self.operation_db.find_or_create(OPHost, {'fqdn': host.fqdn})
        observed_rat = None

        if self._operation.start_type == "wait":
            self.logger.info("Waiting for rat to callback to start operation")
            queue = self.start_listening_for_rat()
            observed_rat = await self.wait_for_rat(queue, {"host": observed_host.id}, None)
        elif self._operation.start_type == "bootstrap":
            self._interface.get_clients(host)
            # write commander
            commander = self.adversary_profile.get_executable_word()
            if not self._operation.start_path:
                self._operation.modify(start_path='C:\\' + commander)

            # clean up pre-existing rat
            for rat_with_colliding_start_path in Rat.objects(active=True, executable=self._operation.start_path):
                # kill rat
                await self._cleaner.delete(rat_with_colliding_start_path)
                self.logger.info("Located a pre-existing RAT already running at {}. Terminating "
                          "pre-existing RAT.".format(self._operation.start_path))

            self.logger.info("Writing commander to: '{}'".format(self._operation.start_path))
            await self._interface.write_commander(host, self._operation.start_path).wait_till_completed()

            if self._operation.user_type == "custom":
                if self._operation.start_user and self._operation.start_password:
                    self._operation.modify(start_user=self._operation.start_user.lower())
                    user_domain, username = self._operation.start_user.split('\\')
                    self.logger.info("Bootstrapping rat with user account: '{}'".format(self._operation.start_user))
                    queue = self.start_listening_for_rat()
                    await self._interface.create_process_as_user(host, self._operation.start_path + " -f", user_domain,
                                                                 username, self._operation.start_password,
                                                                 parent=self._operation.parent_process).wait_till_completed()

                    # simulated operations do a few things:
                    # * mock out a fake rat
                    # * monkey-patch waiting for rats
                    # * monkey-patch the action function for a simulate one - if one exists
                    if get_simulated_domain_data(self._operation.network.domain.windows_domain):
                        host = self.operation_db.find_or_create(OPHost, {'fqdn': host.fqdn})
                        observed_rat = self.operation_db.find_or_create(OPRat, {'host': host, 'elevated': True,
                                                                                'executable': self._operation.start_path,
                                                                                'username': self._operation.start_user,
                                                                                'pid': '9999'})

                        setattr(self, 'wait_for_rat', getattr(self, 'wait_for_simulated_rat'))
                        setattr(self._wrapper, 'drop_file', getattr(self._wrapper, 'drop_simulated_file'))
                        for step in self._steps.values():
                            if getattr(step, 'simulate', None):
                                setattr(step, 'action', getattr(step, 'simulate'))

                    else:
                        observed_rat = await self.wait_for_rat(queue, {"host": observed_host.id,
                                                                       "username": self._operation.start_user}, None)
                else:
                    self.logger.warning("Cannot bootstrap operation with a custom user without username and password")
            elif self._operation.user_type == "active":
                self.logger.info("Bootstrapping rat with active user account")
                queue = self.start_listening_for_rat()
                await self._interface.create_process_as_active_user(host, self._operation.start_path + " -f",
                                                                    parent=self._operation.parent_process).wait_till_completed()
                observed_rat = await self.wait_for_rat(queue, {"host": observed_host.id}, None)
            elif self._operation.user_type == "system" or self._operation.user_type == "inherit":
                if self._operation.user_type == "system":
                    self.logger.info("Bootstrapping rat with SYSTEM account")
                else:
                    self.logger.info("Bootstrapping rat with inherited account")
                # put file and start
                queue = self.start_listening_for_rat()
                await self._interface.create_process(host, self._operation.start_path + " -f",
                                                     parent=self._operation.parent_process).wait_till_completed()

                # wait for a new rat
                observed_rat = await self.wait_for_rat(queue, {"host": observed_host.id, "elevated": True}, None)
            else:
                raise CaseException
            self._operation.modify(start_path=observed_rat.executable)
        elif self._operation.start_type == "existing":
            self.logger.info("Using existing rat to start operation")
            if self._operation.start_rat.host != host:
                self.logger.warning("The starting rat's host does not match the start_host. Making start_host the rat's host.")
                self._operation.modify(start_host=self._operation.start_rat.host)
            self.rat_connected(self._operation.start_rat.to_dict())
            observed_rat = self.ob_of_rat(self._operation.start_rat)
        else:
            raise CaseException
        # In every case, we still need to find or create the observed file for the initial rat callback
        self.operation_db.find_or_create(OPFile, {'host': observed_rat.host, 'path': observed_rat.executable,
                                                  'use_case': 'rat'})
        if (observed_rat.username.startswith(observed_host.hostname.lower()) or
                'nt authority\\system' == observed_rat.username):
            # This is a local account
            self.logger.warning('The rat did not start as a domain user, some steps may not function properly. '
                        'Please start the rat under a Domain Account if full functionality is desired.')
        return observed_rat

    @staticmethod
    def _pin_arguments(func, wrapped_operation, pinned_arguments):
        # Links arguments together for the planner
        sig = inspect.signature(func)
        args = []

        for param in sig.parameters:
            if param == 'operation':
                args.append(wrapped_operation)
            else:
                try:
                    args.append(pinned_arguments[param])
                except KeyError:
                    raise StepParseError("Unspecified argument '{}' in '{}'".format(param, func))
        return args

    async def _perform_next_step(self, planner) -> Optional[Step]:
        """
        This function handles operation step planning, and selects the next step to run

        Returns:
            None
        """
        events = []
        knowns = self.operation_db.all_knowns()
        try:
            for d in knowns:
                dictified = d.to_dict()
                del dictified['_id']
                planner.define_object(_inverse_database_objs[d.__class__].__name__, d.id, dictified)
        except Exception as e:
            self.logger.error("Planner fact error - " + str(e) +". Terminating Operation.")
            planner.undefine_all_objects()
            return None

        time_limit = 120
        self.logger.info("Entering planner")
        self._operation.modify(status_state='planning')
        t1 = time.process_time()
        try:
            next_step, bindings, done_cb = planner.perform_best_step(self.planner_depth, time_limit)
        except Exception as e:
            self.logger.error("Unexpected Planner Error - " + str(e) + ". Terminating Operation.")
            return None
        finally:
            t2 = time.process_time()
            self.logger.info("Planning time took: {} seconds".format(t2 - t1))
            planner.undefine_all_objects()

        if not next_step or not bindings or not done_cb:
            # no more plans
            self._operation.modify(planner_facts="\n".join(str(x) for x in planner.get_dump()))
            return None

        precond_names = {k: _database_objs[v] if isinstance(v, type) else _database_objs[type(v)] for k, v in
                         next_step.preconditions}
        pinned_arguments = {}
        precondition_objects = {}
        step_params = {}
        for name, obj_id in bindings.items():
            db_class = precond_names[name]
            pinned_arguments[name] = db_class.objects.with_id(obj_id)
            precondition_objects[name] = pinned_arguments[name]
            step_params[name] = obj_id

        step_idx = len(self._operation.performed_steps)

        for condition in next_step.postconditions:
            if len(condition) == 2:
                name = condition[0]
                value = condition[1]
            else:
                raise StepParseError("Precondition had invalid length: {}".format(len(condition)))

            step_params[name] = []

            event = None
            if value == OPFile or isinstance(value, OPFile):
                event = [self.start_file_event(), None]
                events.append(event)
            elif value == OPRegKey or isinstance(value, OPRegKey):
                event = [self.start_reg_event(), None]
                events.append(event)

            queue = None
            if value == OPRat or isinstance(value, OPRat):
                queue = self.start_listening_for_rat()

            # It looks weird to repeat name, but it is necessary, otherwise the last value of name is always used
            # instead of the value of name on each iteration of the loop
            def obj_call(x, name=name):
                self._operation.modify(**{'push__performed_steps__{}__params__{}'.format(step_idx, name): x.id})

            pinned_arguments[name] = functools.partial(self.postcondition_callback, value, pinned_arguments, event,
                                                       queue, obj_call)

        desc_args = self._pin_arguments(next_step.description, self._wrapper, pinned_arguments)
        description = next_step.description(*desc_args)

        # get the pinned arguments and replace the keywords in the function with them
        args = self._pin_arguments(next_step.action, self._wrapper, pinned_arguments)
        self.logger.info("Running step {} at {}".format(next_step.display_name, util.tz_utcnow().isoformat()))
        self._operation.modify(status_state='execution')
        self._operation.modify(
            push__performed_steps={"name": next_step.__name__, "description": description, "status": "running",
                                   "params": step_params, "step": CodedStep.objects.get(name=next_step.__name__)})

        idx = len(self._operation.performed_steps) - 1

        def job_append(x):
            self._operation.modify(**{'push__performed_steps__{}__jobs'.format(idx): x})

        # BSF logging: build a step event for this step
        # technique labelling
        id_tactic = defaultdict(list)
        for tech_id, tactic in next_step.attack_mapping:
            id_tactic[tech_id].append(tactic)
        id_names = {}
        for tech_id in id_tactic:
            id_names[tech_id] = AttackTechnique.objects(technique_id=tech_id).first().name
        attack_info = [event_logging.AttackReference(tech_id, id_names[tech_id], tactics) for tech_id, tactics in
                       id_tactic.items()]
        # extract dest_host (hosts in preconditions that don't match rat hosts)
        rat_hosts = [r.host.fqdn.lower() for r in precondition_objects.values() if isinstance(r, ObservedRat)]
        other_hosts = [h.fqdn.lower() for h in precondition_objects.values() if isinstance(h, ObservedHost)]
        other_hosts = [h for h in other_hosts if h not in rat_hosts]
        if len(other_hosts) >= 1:
            dest_hosts = [h for h in other_hosts]
        else:
            dest_hosts = None
        self.bsf_emitter.add_step(event_logging.Step(attack_info, dest_hosts=dest_hosts, description=description))

        self._interface.register_callback(job_append)

        success = False
        try:
            success = await next_step.action(*args)
        except RatDisconnectedError as e:
            self.logger.warning("Tried to execute on a disconnected rat")
            # mark rat as dead
            self.rat_disconnected(e.args[0])
        except JobException:
            self.logger.warning("Job failed")
            time.sleep(10)
        except parsers.ParseError as err:
            self.logger.warning("Failed to parse with error: '{}'".format(err))
            time.sleep(10)
        except tuple(m[1] for m in inspect.getmembers(errors, inspect.isclass) if isinstance(m[1](), Exception)) as e:
            # catch all possible parser exceptions here
            exception_name = type(e).__name__
            exception_value = str(e)
            if exception_value:
                exception_value = ': ' + exception_value
            self.logger.warning("Failed to parse with error: " + exception_name + exception_value)
            time.sleep(10)
        except RatCallbackTimeoutError:
            self.logger.warning("Failed to get rat callback")

        self._interface.unregister_callback(job_append)

        new_status = "success" if success else "failed"
        self._operation.modify(**{'set__performed_steps__{}__status'.format(idx): new_status})
        self.logger.info("Returned from {} at {}".format(next_step.display_name, util.tz_utcnow().isoformat()))
        for event in events:
            self.end_event(event[0], event[1])

        if not success:
            temp = []
            for entry in args[1:]:
                if not isinstance(entry, functools.partial):
                    temp.append(entry)
            if (next_step.display_name, tuple(temp)) in self.local_mapping:
                self.local_mapping[(next_step.display_name, tuple(temp))] += 1
            else:
                self.local_mapping[(next_step.display_name, tuple(temp))] = 1
            if self.local_mapping[(next_step.display_name, tuple(temp))] >= self.recursion_limit:
                self._operation.modify(**{'push__failed_actions': {'name': next_step.display_name, 'parameters': temp}})

        done_cb(success=success)
        return next_step

    async def postcondition_callback(self, value: Union[Type[Keyword], Keyword], pinned_arguments,
                                     event: event_logging.Event, queue: asyncio.Queue = None, obj_call: Callable = None,
                                     obj_dict=None):
        """
        This gem of a function is called when a postcondition function is called. It evaluates the type of the
        postcondition and performs the steps necessary to create the post-condition, notably finding or creating the
        postcondition in the database, for a OPExec post-condition, waiting for the callback, and firing any events
        that need to be notified that this post-condition has been completed.

        Args:
            value: The post-condition
            pinned_arguments: the pre-conditions passed into the step
            event: any event that may need to be finalized
            queue: any waiting queue for a rat
            obj_call: a function that will be called with the obj of any objects created by this post-condition
            obj_dict: a dict of fields that are passed in from the step on object creation

        Returns: The object that was created as a result of this post-condition being called
        """
        if not obj_dict:
            obj_dict = {}
        if isinstance(value, OPVar):
            return
        if isinstance(value, type):
            obj = self.operation_db.find_or_create(value, obj_dict)
            if obj_call:
                obj_call(obj)
        else:
            delayed = ()
            remote_file_fields = {'src_host': None, 'src_path': None}
            if isinstance(value.obj, dict):
                for k, v in value.obj.items():
                    if k == '$in':
                        delayed = v.obj.split(".")
                    else:
                        obj_dict[k] = self.resolve_expression(pinned_arguments, v)
                if isinstance(value, OPRat):
                    if 'host' in obj_dict:
                        obj_dict['host'] = obj_dict['host'].id
                    #  This can throw a RatCallbackTimeout error so that the operation_step can know if it didn't get
                    #    the callback it was waiting for and react appropriately
                    obj = await self.wait_for_rat(queue, obj_dict, 120)  # TODO: Make this timeout configurable!
                else:
                    if isinstance(value, OPFile):
                        remote_file_fields = {k: obj_dict[k] for k in remote_file_fields.keys() if k in obj_dict}
                        for k in remote_file_fields.keys():
                            del obj_dict[k]
                    obj = self.operation_db.find_or_create(type(value), obj_dict)
                    if obj_call:
                        obj_call(obj)
            else:
                obj = self.resolve_expression(pinned_arguments, value)
                obj.update(**obj_dict)
            if delayed:
                db_obj = self.resolve_expression(pinned_arguments, OPVar(delayed[0]))
                db_obj.update(**{"push__" + delayed[1]: obj})
            for k, v in remote_file_fields.items():
                if v:
                    setattr(obj, k, v)
        if event and len(event) >= 2:
            event[1] = obj
        return obj

    def resolve_expression(self, pinned_arguments, value):
        """Resolves provided arguments to python base objects/database entries"""
        _resolve = functools.partial(ServerOperation.resolve_expression, pinned_arguments)
        if isinstance(value, dict):
            dct = {}
            for x, y in value.items():
                dct[_resolve(x)] = _resolve(y)
            return dct
        elif isinstance(value, list):
            lst = []
            for x in value:
                lst.append(_resolve(x))
            return lst
        elif isinstance(value, OPVar):
            elems = value.obj.split('.')
            obj = pinned_arguments[elems.pop(0)]
            for el in elems:
                obj = getattr(obj, el)
            return obj
        elif isinstance(value, str) or isinstance(value, bool):
            return value
        else:
            for key in _database_objs:
                if isinstance(value, key):
                    resolved = _resolve(value.obj)
                    try:
                        if value.obj == {}:
                            return self.operation_db.find_many(type(value), resolved)
                        else:
                            return self.operation_db.find_one(type(value), resolved)
                    except IndexError:
                        raise StepParseError("Criterion could not be satisfied: {}({})".format(type(value), resolved))

            raise Exception("type not found: {}".format(type(value)))

    def start_listening_for_rat(self):
        queue = asyncio.Queue()
        self._rat_waiters.append(queue)
        return queue

    async def wait_for_simulated_rat(self, queue: asyncio.Queue, obj_dict, timeout: Union[int, None]) -> ObservedRat:
        obj_dict['pid'] = '9999'
        return self.operation_db.find_or_create(OPRat, obj_dict)

    async def wait_for_rat(self, queue: asyncio.Queue, obj_dict, timeout: Union[int, None]) -> ObservedRat:
        #  quick function to make sure we return the correct rat, not just the first rat to callback
        #    this is called with a timeout value so that this doesn't turn into an infinite loop
        async def pop_loop():
            while True:
                item = await queue.get()
                if util.nested_cmp(item.to_dict(), obj_dict):
                    return item

        # don't infinitely loop while waiting for a rat, timeout after a configurable number of seconds
        if timeout is not None and timeout <= 0:
            raise InvalidTimeoutExceptionError("Invalid timeout value for new rat: {}".format(str(int)))
        try:
            return await asyncio.wait_for(pop_loop(), timeout)
        except asyncio.TimeoutError:
            raise RatCallbackTimeoutError
        finally:
            self._rat_waiters.remove(queue)

    def pair_rat(self, rat_dict: Dict) -> ObservedRat:
        # check for an existing mapping first
        for x in self._operation.rat_iv_map:
            if x.rat == rat_dict["_id"]:
                # this is old news, so return now
                return x.observed_rat

        # convert host
        fqdn = Host.objects.with_id(rat_dict["host"]).fqdn
        host = self.operation_db.find_or_create(OPHost, {'fqdn': fqdn})
        ob_rat = self.operation_db.find_or_create(OPRat, {'host': host, 'elevated': rat_dict["elevated"],
                                                          'executable': rat_dict["executable"],
                                                          'username': rat_dict["username"],
                                                          'pid': rat_dict["name"]})

        self._operation.modify(push__rat_iv_map={"observed_rat": ob_rat, "rat": rat_dict["_id"]})
        return ob_rat

    def rat_of_ob(self, observed_rat: ObservedRat) -> Rat:
        """
        Returns the rat that matches the ObservedRat.

        Args:
            observed_rat: The rat identifier to find the rat of

        Returns:
            the rat
        """
        for x in self._operation.rat_iv_map:
            if x.observed_rat == observed_rat:
                if x.rat.active:
                    return x.rat
                else:
                    raise RatDisconnectedError(x._data['rat'].id)
        raise Exception("Could not find rat")

    def ob_of_rat(self, rat: Rat) -> ObservedRat:
        """
        Returns the ObservedRat for a given rat

        Args:
            rat: the rat

        Returns:
            The ObservedRat associated with the provided rat
        """
        for x in self._operation.rat_iv_map:
            if x.rat == rat:
                # this is old news, so return now
                return x.observed_rat
        raise Exception("Could not find observedRat")

    def ob_of_host(self, host: Host) -> ObservedHost:
        """
        Returns the ObservedHost for a given host

        Args:
            host: the host

        Returns:
            The ObservedHost associated with the provided host
        """
        for x in self._operation.get('known_hosts', []):
            if x.fqdn == host.fqdn:
                return x
        raise Exception("Could not find observedHost")

    def host_of_ob(self, obhost: ObservedHost) -> Host:
        """
        Returns the Host for a given ObservedHost

        Args:
            obhost: the ObservedHost

        Returns:
            The Host associated with the provided ObservedHost
        """
        for x in Host.objects():
            if x.fqdn == obhost.fqdn:
                return x
        raise Exception("Could not find Host")

    @staticmethod
    def start_file_event() -> event_logging.FileEvent:
        return event_logging.FileEvent(fqdn=None, file_path=None)

    @staticmethod
    def start_reg_event() -> event_logging.RegistryEvent:
        return event_logging.RegistryEvent(fqdn=None, key=None, data=None, value=None)

    def end_event(self, event: event_logging.Event, observable: Union[ObservedRegKey, ObservedFile] = None) -> None:
        """Finalizes the logging of an event"""
        if not observable:
            event.end(False)
        else:
            if isinstance(observable, ObservedRegKey):
                event.update(host=observable.host.fqdn, fqdn=observable.host.fqdn, key=observable.key,
                             data=observable.data,
                             value=observable.value)
            elif isinstance(observable, ObservedFile):
                event.update(host=observable.host.fqdn, fqdn=observable.host.fqdn, file_path=observable.path)
            event.end(True)
        self.log_event(event)

    def log_step(self, step: event_logging.Step) -> None:
        self.bsf_emitter.add_step(step)

    def log_event(self, event: event_logging.Event) -> None:
        self.bsf_emitter.add_event(event)

    def filter_fqdns(self, fqdns: List[str]) -> List[str]:
        """Filters fqdns to those included in an operation"""
        network = self._operation.network
        hosts = {host.fqdn for host in network.hosts}
        return [x for x in fqdns if x in hosts]

    # Create a simple HTTP server at the beginning of an operation to handle request
    def create_exfil_server(self, port: str, method: str) -> socketserver.TCPServer:
        handler = http.server.SimpleHTTPRequestHandler
        exfil_server = socketserver.TCPServer(("0.0.0.0", int(port)), handler)
        if method == "https":
            exfil_server.socket = ssl.wrap_socket(exfil_server.socket,
                                                  certfile='conf/cert.pem',
                                                  server_side=True,
                                                  keyfile='conf/key.pem')
        return exfil_server


class OperationDB(object):
    def __init__(self, operation, logger):
        self._operation = operation
        self.logger = logger

    def all_knowns(self):
        """This function returns all 'known' type objects associated with a operation"""
        retval = []
        for value in _knowns.values():
            retval += self._operation.get(value, [])
        return retval

    def find_one(self, db_class: Type[Keyword], query: dict):
        """This function returns the first match in the database"""
        return self.find_many(db_class, query)[0]

    def find_many(self, db_class: Type[Keyword], query: dict):
        """This function returns all matches for a query in the database"""
        db_class = _database_objs[db_class]
        knowns = self._operation[_knowns[db_class]]
        filter_query = {'id__in': [x.id for x in knowns]}
        filter_query.update(query)
        return list(db_class.objects(**filter_query))

    def combine_objects(self, objects: List[ExtrovirtsDocument]):
        """
        This function combines equivalent objects in the database to prevent duplication

        Returns:
            The list of objects after coalescing duplicates
        """
        combined_obj = {}
        rewrite = {}

        if len(objects) == 2:
            assert objects[0] != objects[1]
        self.logger.info("Combining: {}".format(objects))

        if len(objects) == 1:
            self.logger.warning("Tried to combine a single object {}".format(objects[0]))
            return objects[0]

        # save references to objects that are merged together
        for obj in objects[1:]:
            self._operation.modify(**{"object_references__{}".format(obj.id): objects[0].id})

        # combine the fields of all the objects
        for index, item in enumerate(objects):
            dictified = item.to_dict(dbref=True)
            del dictified["_id"]
            combined_obj.update(dictified)
            if index != 0:
                rewrite[item] = objects[0]
                db_class = type(item)
                self._operation.update(**{"pull__" + _knowns[db_class]: item})
                item.delete()
        objects[0].update(**combined_obj)

        # rewrite all of the ReferenceFields to any of the combined objects that are now deleted
        all_dirty = defaultdict(list)
        for old_object, new_object in rewrite.items():
            rules = _database_reference_fields[type(old_object)]
            for db_class, field_type, field_name in rules:
                knowns = self._operation[_knowns[db_class]]

                # in the case that the field is a list mongoengine accepts a single value for list fields and returns
                # all objects that contain that element which makes it so we don't have to explicitly use $all
                dirty_objects = list(db_class.objects(**{'id__in': [x.id for x in knowns], field_name: old_object}))
                all_dirty[db_class] += dirty_objects
                if field_type == "field":
                    for dirty in dirty_objects:
                        dirty.update(**{field_name: new_object})
                else:
                    for dirty in dirty_objects:
                        dirty.update(**{"pull__" + field_name: old_object})
                        dirty.update(**{"push__" + field_name: new_object})

        # any objects whose ReferenceFields were updated may now be made equivalent
        for db_class, dirty_objects in all_dirty.items():
            while len(dirty_objects):
                dirty_object = dirty_objects.pop()
                # not sure why but dirty_object has to be reloaded here
                dirty_object.reload()
                knowns = self._operation[_knowns[db_class]]

                # find any objects equivalent to the current dirty object
                equivalent_objs = self.ob_equivalent(dirty_object, {
                    'id__in': [x.id for x in knowns if x not in dirty_objects and x.id != dirty_object.id]})
                if equivalent_objs:
                    self.combine_objects([dirty_object] + equivalent_objs)

        return objects[0]

    # finds objects that obj is equivalent to within the query set
    @classmethod
    def ob_equivalent(cls, obj: ExtrovirtsDocument, query: dict):
        db_class = type(obj)
        dictified = obj.to_dict(dbref=True)
        del dictified['_id']
        return cls.dict_equivalent(db_class, dictified, query)

    # finds objects that the dict is equivalent to within the query set
    @staticmethod
    def dict_equivalent(db_class: Type[ExtrovirtsDocument], dictified: dict, query: dict):
        retrieved_items = set()
        if hasattr(db_class, "distinct_fields"):
            for fields in db_class.distinct_fields:
                all_fields_in_obj = all([x in dictified for x in fields])
                if not all_fields_in_obj:
                    continue
                db_query = {k: dictified[k] for k in fields}
                db_query.update(query)
                retrieved_items |= set(db_class.objects(**db_query))
        else:
            db_query = {}
            db_query.update(dictified)
            db_query.update(query)
            retrieved_items = set(db_class.objects(**db_query))
        return list(retrieved_items)

    # Locates or creates a database object
    def find_or_create(self, db_class: Type[Keyword], query: dict) -> mongoengine.Document:
        db_class = _database_objs[db_class]
        knowns = self._operation[_knowns[db_class]]
        retrieved_list = []
        if query:
            retrieved_list = self.dict_equivalent(db_class, query, {'id__in': [x.id for x in knowns]})
            if len(retrieved_list) > 1:
                retrieved_list = [self.combine_objects(retrieved_list)]
            if retrieved_list:
                retrieved_list[0].modify(**query)

        if len(retrieved_list) == 0:
            retrieved_list = [db_class(**query).save()]
            knowns.append(retrieved_list[0])
            self._operation.modify(**{"push__" + _knowns[db_class]: retrieved_list[0]})
        return retrieved_list[0]
