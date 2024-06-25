import pytest
from sigma.collection import SigmaCollection
from sigma.backends.quickwit import QuickwitBackend


@pytest.fixture
def quickwit_backend():
    return QuickwitBackend()


def test_quickwit_and_expression(quickwit_backend: QuickwitBackend):
    assert quickwit_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA: valueA
                    fieldB: valueB
                condition: sel
        """)
    ) == ['fieldA:"valueA" AND fieldB:"valueB"']


def test_quickwit_or_expression(quickwit_backend: QuickwitBackend):
    assert quickwit_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel1:
                    fieldA: valueA
                sel2:
                    fieldB: valueB
                condition: 1 of sel*
        """)
    ) == ['fieldA:"valueA" OR fieldB:"valueB"']


def test_quickwit_and_or_expression(quickwit_backend: QuickwitBackend):
    assert quickwit_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA:
                        - valueA1
                        - valueA2
                    fieldB:
                        - valueB1
                        - valueB2
                condition: sel
        """)
    ) == ["fieldA:IN [valueA1 valueA2] AND fieldB:IN [valueB1 valueB2]"]


def test_quickwit_or_and_expression(quickwit_backend: QuickwitBackend):
    assert quickwit_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel1:
                    fieldA: valueA1
                    fieldB: valueB1
                sel2:
                    fieldA: valueA2
                    fieldB: valueB2
                condition: 1 of sel*
        """)
    ) == [
               '(fieldA:"valueA1" AND fieldB:"valueB1") OR (fieldA:"valueA2" AND fieldB:"valueB2")'
           ]


def test_quickwit_in_expression(quickwit_backend: QuickwitBackend):
    assert quickwit_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA:
                        - valueA
                        - valueB
                        - valueC*
                condition: sel
        """)
    ) == ["fieldA:IN [valueA valueB valueC*]"]


def test_quickwit_regex_query(quickwit_backend: QuickwitBackend):
    assert quickwit_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA|re: foo.*bar
                    fieldB: foo
                condition: sel
        """)
    ) == ['fieldA:/foo.*bar/ AND fieldB:"foo"']


def test_quickwit_cidr_query(quickwit_backend: QuickwitBackend):
    assert quickwit_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    field|cidr: 192.168.0.0/16
                condition: sel
        """)
    ) == ["field:[192.168.0.0 TO 192.168.255.255]"]


def test_quickwit_field_name_with_whitespace(quickwit_backend: QuickwitBackend):
    assert quickwit_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    field name: value
                condition: sel
        """)
    ) == ['"field name":"value"']


def test_quickwit_wildcard_query(quickwit_backend: QuickwitBackend):
    assert quickwit_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA: value*
                condition: sel
        """)
    ) == ['fieldA:"value*"']


def test_quickwit_range_query(quickwit_backend: QuickwitBackend):
    assert quickwit_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA|gt: 100
                    fieldB|lt: 200
                condition: sel
        """)
    ) == ["fieldA:>100 AND fieldB:<200"]


def test_quickwit_not_query(quickwit_backend: QuickwitBackend):
    assert quickwit_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA: valueA
                condition: not sel
        """)
    ) == ['NOT fieldA:"valueA"']


def test_quickwit_wildcards(quickwit_backend: QuickwitBackend):
    assert quickwit_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA: "value*"
                    fieldB: "*value"
                    fieldC: "*val*ue*"
                condition: sel
        """)
    ) == ['fieldA:"value*" AND fieldB:"*value" AND fieldC:"*val*ue*"']


def test_quickwit_or_with_wildcards(quickwit_backend: QuickwitBackend):
    assert quickwit_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel1:
                    fieldA: "value*"
                sel2:
                    fieldB: "*value"
                condition: 1 of sel*
        """)
    ) == ['fieldA:"value*" OR fieldB:"*value"']


def test_quickwit_not_expression(quickwit_backend: QuickwitBackend):
    assert quickwit_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA: valueA
                filter:
                    fieldB: valueB
                condition: sel and not filter
        """)
    ) == ['fieldA:"valueA" AND NOT fieldB:"valueB"']



def test_quickwit_exists_expression(quickwit_backend: QuickwitBackend):
    assert quickwit_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA: '*'
                condition: sel
        """)
    ) == ['fieldA:*']


def test_quickwit_value_with_spaces(quickwit_backend: QuickwitBackend):
    assert quickwit_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA: 'value with spaces'
                condition: sel
        """)
    ) == ['fieldA:"value with spaces"']


def test_quickwit_multiple_values(quickwit_backend: QuickwitBackend):
    assert quickwit_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA:
                        - valueA1
                        - valueA2
                    fieldB: valueB
                condition: sel
        """)
    ) == ['fieldA:IN [valueA1 valueA2] AND fieldB:"valueB"']


def test_quickwit_value_modifiers(quickwit_backend: QuickwitBackend):
    assert quickwit_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA|contains: value
                    fieldB|endswith: end
                    fieldC|startswith: start
                condition: sel
        """)
    ) == ['fieldA:"*value*" AND fieldB:"*end" AND fieldC:"start*"']


def test_quickwit_null_values(quickwit_backend: QuickwitBackend):
    assert quickwit_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA: null
                condition: sel
        """)
    ) == ['NOT fieldA:*']
