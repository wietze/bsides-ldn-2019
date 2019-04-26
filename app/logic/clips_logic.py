import copy
from clips import Environment
from plugins.adversary.app.logic.logic import Variable, Comparison, Term, Expression, LogicContext, Rule, Unary


def expr_terms(expr: Expression):
    if isinstance(expr, Comparison) and expr.comparator == '&':
        return "(and {} {})".format(expr_terms(expr.obj1), expr_terms(expr.obj2))
    elif isinstance(expr, Comparison) and expr.comparator == '|':
        return "(or {} {})".format(expr_terms(expr.obj1), expr_terms(expr.obj2))
    elif isinstance(expr, Comparison) and expr.comparator == '!=':
        return "(test (neq {} {}))".format(expr_terms(expr.obj1), expr_terms(expr.obj2))
    elif isinstance(expr, Unary) and expr.operator == '~':
        return '(not {})'.format(expr_terms(expr.obj1))
    elif isinstance(expr, Term):
        return convert_term(expr)
    elif isinstance(expr, Variable):
        return convert_variable(expr)
    else:
        raise Exception


def convert_variable(var):
    return "?{}".format(var)


def convert_literal(lit):
    if isinstance(lit, Variable):
        return convert_variable(lit)
    elif isinstance(lit, bool):
        return "{}".format(lit)
    elif isinstance(lit, int):
        return "{}".format(lit)
    else:
        return escape_string(lit)


def escape_string(lit):
    lit = lit.replace("\\", "\\\\")
    lit = lit.replace('"', '\\"')
    return '"' + lit + '"'


def convert_term(term):
    return "({} {})".format(term.predicate, " ".join([convert_literal(x) for x in term.literals]))


class CLIPSContext(LogicContext):
    def __init__(self):
        self.env = Environment()

    def define_rule(self, rule: Rule):
        rule_conds = expr_terms(rule.body)

        cons = "(defrule {0} {1} => (assert ({0} {2})))".format(rule.name, '(logical {})'.format(rule_conds),
                                                                " ".join(["?" + x.name for x in rule.parameters]))
        self.env.define_construct(cons)

    def assert_fact(self, fact: Term):
        self.env.define_fact("({} {})".format(fact.predicate, " ".join([convert_literal(x) for x in fact.literals])))

    def retract_fact(self, fact: Term):
        self.env.retract_fact("({} {})".format(fact.predicate, " ".join([convert_literal(x) for x in fact.literals])))

    def retract_all_facts(self):
        self.env.reset()

    def query(self, expression: Expression):
        if not isinstance(expression, Term):
            raise Exception('CLIPS only supports querying terms or rules')

        self.env.run()
        return copy.copy(self.env.check_facts(expression.predicate))

    def define_predicate(self, name: str, arity: int):
        pass

    def get_facts(self):
        return self.env.get_facts()

    def close(self):
        del self.env
