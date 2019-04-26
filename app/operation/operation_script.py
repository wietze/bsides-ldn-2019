from plugins.adversary.app.operation import operation as operation_intf
from collections import defaultdict


class Planner(object):
    """
    Planner class
    """
    def __init__(self, planner, logic_context_factory):
        # the steps that the planner can use
        self._planner = planner
        self._logic_context_factory = logic_context_factory
        self.recursion_limit = 2
        self._performed_actions = None
        self.planner_context = None
        self.initialized = False

        # public variable, may be inspected or modified
        self.steps = []

    def configure(self, **kwargs):
        """
        Sets configuration variables for the planner
        """
        raise NotImplementedError

    def generate_plan(self, depth: int):
        """Plans, returning the action that the planners thinks should be executed, or None if no action can be
        executed. Searches to the given depth."""
        raise NotImplementedError

    def forward_search(self, depth: int):
        """Returns all possible plans. Searching at the given depth"""
        raise NotImplementedError

    def initialize(self, operation):
        if not self.initialized:
            self.planner_context = self._planner(self._logic_context_factory(), self.recursion_limit,
                                                 performed_actions=self._performed_actions)
            operation.initialize_planner(self.planner_context, [s._step for s in self.steps])
        self.initialized = True


class Operation(object):
    """
    Operation class
    """
    def __init__(self, operation):
        self._operation = operation

    def run(self, planner, goal=None, pause=False):
        """Runs actions, taking instructions from the planner. If a goal is provided it
        is given to the planner. If pause is True, this function returns after running one action.
        Otherwise it runs until either the goal is achieved or the available actions are exhausted."""
        planner.initialize(self._operation)
        performed_step = self._operation._perform_next_step(planner.planner_context)
        if not pause:
            # continue until no more actions
            while performed_step is not None:
                performed_step = self._operation._perform_next_step(planner.planner_context)
        return performed_step

    def execute_action(self, action):
        """Executes the given action"""
        raise NotImplementedError

    @property
    def state(self):
        """Returns a list of objects in the state"""
        knowns = self._operation.operation_db.all_knowns()
        state_dict = defaultdict(list)
        for d in knowns:
            obj_name = operation_intf._inverse_database_objs[d.__class__].__name__
            state_dict[obj_name].append(d.to_dict())

        # quick way to stop making it be a defaultdict without completely converting to a dict
        state_dict.default_factory = None
        return state_dict

    @property
    def previous_steps(self):
        """Returns a list of the previously executed steps"""
        return [x.to_mongo().to_dict() for x in self._operation._operation.performed_steps]

    def goal_satisfied(self, goal):
        """Checks whether the goal is satisfied in the current state"""
        raise NotImplementedError


class Step(object):
    """
    Step class
    """
    def __init__(self, _step):
        self._step = _step
        self.name = _step.__name__


class CalderaInterface(object):
    """
    Caldera Interface Class
    """
    def __init__(self, planner_factories, operation, steps, logic_context_factory):
        self.planners = [Planner(planner, logic_context_factory) for planner in planner_factories]
        self.operation = Operation(operation)
        self.steps = {s.name: s for s in [Step(step) for step in steps]}


class ScriptContext(object):
    """
    Script Context
    """
    def __init__(self, planner_factories, operation, steps, logic_context_factory):
        self.planner_factories = planner_factories
        self.operation = operation
        self.steps = steps
        self.logic_context_factory = logic_context_factory

    def get_locals_dict(self):
        return {
            'interface': CalderaInterface(self.planner_factories, self.operation, self.steps,
                                          self.logic_context_factory)
        }

    def run(self, script):
        exec(script, {}, self.get_locals_dict())
