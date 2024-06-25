import ipaddress

from sigma.conditions import (
    ConditionItem,
    ConditionAND,
    ConditionOR,
    ConditionNOT,
    ConditionFieldEqualsValueExpression,
)
from sigma.conversion.base import TextQueryBackend
from sigma.types import SigmaCompareExpression, SigmaString
from sigma.conversion.state import ConversionState
from sigma.rule import SigmaRule
from typing import ClassVar, Dict, Union, List, Any, Pattern
import re


class QuickwitBackend(TextQueryBackend):
    """Quickwit backend."""

    name: ClassVar[str] = "Quickwit backend"
    formats: Dict[str, str] = {
        "default": "Plain Quickwit queries",
    }
    requires_pipeline: bool = False

    precedence: ClassVar[tuple[ConditionItem, ConditionItem, ConditionItem]] = (
        ConditionNOT,
        ConditionAND,
        ConditionOR,
    )
    group_expression: ClassVar[str] = "({expr})"

    token_separator: str = " "
    or_token: ClassVar[str] = "OR"
    and_token: ClassVar[str] = "AND"
    not_token: ClassVar[str] = "NOT"
    eq_token: ClassVar[str] = ":"

    str_quote: ClassVar[str] = '"'
    escape_char: ClassVar[str] = "\\"
    wildcard_multi: ClassVar[str] = "*"
    wildcard_single: ClassVar[str] = "*"
    add_escaped: ClassVar[str] = "\\"
    filter_chars: ClassVar[str] = ""

    re_expression: ClassVar[str] = "{field}:/{regex}/"
    re_escape_char: ClassVar[str] = "\\"
    re_escape: ClassVar[tuple[str]] = ("/",)

    compare_op_expression: ClassVar[str] = "{field}{operator}{value}"
    compare_operators: ClassVar[Dict[SigmaCompareExpression.CompareOperators, str]] = {
        SigmaCompareExpression.CompareOperators.LT: "<",
        SigmaCompareExpression.CompareOperators.LTE: "<=",
        SigmaCompareExpression.CompareOperators.GT: ">",
        SigmaCompareExpression.CompareOperators.GTE: ">=",
    }

    field_null_expression: ClassVar[str] = "NOT {field}:*"
    field_exists_expression: ClassVar[str] = "{field}:*"
    field_not_exists_expression: ClassVar[str] = "NOT {field}:*"

    convert_or_as_in: ClassVar[bool] = True
    convert_and_as_in: ClassVar[bool] = False
    in_expressions_allow_wildcards: ClassVar[bool] = True
    field_in_list_expression: ClassVar[str] = "{field}:IN [{list}]"
    or_in_operator: ClassVar[str] = "IN"
    list_separator: ClassVar[str] = " "

    # Quoting
    field_quote: ClassVar[str] = '"'
    field_quote_pattern: ClassVar[Pattern] = re.compile("^\\w+$")

    def convert_condition_field_eq_val_str(
        self, cond: ConditionFieldEqualsValueExpression, state: ConversionState
    ) -> Union[str, Any]:
        """Conversion of field = string value expressions"""
        field = self.escape_and_quote_field(cond.field)
        if cond.value == "*":  # Handle exists expression
            return f"{field}:*"
        elif cond.value.startswith("*") or cond.value.endswith("*"):  # Handle wildcards
            return f'{field}:"{self.convert_value_str(cond.value, state)}"'
        else:
            return f'{field}:"{self.convert_value_str(cond.value, state)}"'

    def convert_condition_or(
        self, cond: ConditionOR, state: ConversionState
    ) -> Union[str, Any]:
        """Conversion of OR conditions"""
        return f" {self.or_token} ".join(
            self.group_expression.format(expr=self.convert_condition(arg, state))
            if isinstance(arg, ConditionAND)
            else self.convert_condition(arg, state)
            for arg in cond.args
        )

    def convert_condition_and(
        self, cond: ConditionAND, state: ConversionState
    ) -> Union[str, Any]:
        """Conversion of AND conditions"""
        return f" {self.and_token} ".join(
            self.convert_condition(arg, state) for arg in cond.args
        )

    def convert_condition_field_eq_val_cidr(
        self, cond: ConditionFieldEqualsValueExpression, state: ConversionState
    ) -> Union[str, Any]:
        """Conversion of CIDR expressions"""
        cidr = ipaddress.ip_network(cond.value.cidr)
        return f"{cond.field}:[{cidr.network_address} TO {cidr.broadcast_address}]"

    def escape_and_quote_field(self, field_name: str) -> str:
        """Escape and quote field names if they contain spaces or special characters."""
        if " " in field_name or any(
            char in field_name for char in '+-&|!(){}[]^"~*?:\\'
        ):
            return f'"{field_name}"'
        return field_name

    def convert_condition_field_compare_op_val(
        self, cond: ConditionFieldEqualsValueExpression, state: ConversionState
    ) -> Union[str, Any]:
        """Conversion of field matches compare operation value expressions"""
        return self.compare_op_expression.format(
            field=cond.field + self.eq_token,
            operator=self.compare_operators[cond.value.op],
            value=cond.value.number,
        )

    def convert_value_str(self, value: SigmaString, state: ConversionState) -> str:
        """Convert a SigmaString into a plain string which can be used in query"""
        converted = value.convert(
            self.escape_char,
            self.wildcard_multi,
            self.wildcard_single,
            self.add_escaped,
            self.filter_chars,
        )
        return converted

    def convert_condition_as_in_expression(
        self, cond: Union[ConditionOR, ConditionAND], state: ConversionState
    ) -> Union[str, Any]:
        """Conversion of OR or AND conditions into in-expressions"""
        return self.field_in_list_expression.format(
            field=cond.args[0].field,
            list=self.list_separator.join(
                [self.convert_value_str(arg.value, state) for arg in cond.args]
            ),
        )

    def convert_condition_not(
        self, cond: ConditionNOT, state: ConversionState
    ) -> Union[str, Any]:
        """Conversion of NOT conditions"""
        expr = self.convert_condition(cond.args[0], state)
        return f"NOT {expr}"

    def finalize_query(
        self,
        rule: SigmaRule,
        query: Any,
        index: int,
        state: ConversionState,
        output_format: str,
    ) -> Any:
        """Finalize query by adding any necessary prefixes or suffixes."""
        return query

    def finalize_output_default(self, queries: List[Any]) -> Any:
        """Finalize the output for the default format."""
        return queries
