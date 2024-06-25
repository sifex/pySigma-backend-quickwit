import pytest
from sigma.collection import SigmaCollection
from sigma.backends.quickwit import QuickwitBackend
from sigma.pipelines.quickwit import quickwit_windows_pipeline


@pytest.fixture
def quickwit_backend():
    return QuickwitBackend(quickwit_windows_pipeline())


def test_quickwit_windows_eventid(quickwit_backend):
    assert quickwit_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test EventID
            status: test
            logsource:
                product: windows
                service: security
            detection:
                sel:
                    EventID: 4624
                condition: sel
        """)
    ) == ["winlog.event_id:4624"]


def test_quickwit_windows_image(quickwit_backend):
    assert quickwit_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test Image
            status: test
            logsource:
                product: windows
                service: sysmon
            detection:
                sel:
                    Image: C:\\Windows\\System32\\cmd.exe
                condition: sel
        """)
    ) == ['process.executable:"C:\\\\Windows\\\\System32\\\\cmd.exe"']


def test_quickwit_windows_commandline(quickwit_backend):
    assert quickwit_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test CommandLine
            status: test
            logsource:
                product: windows
                service: sysmon
            detection:
                sel:
                    CommandLine: '*whoami*'
                condition: sel
        """)
    ) == ['process.command_line:"*whoami*"']


def test_quickwit_windows_originalfilename(quickwit_backend):
    assert quickwit_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test OriginalFileName
            status: test
            logsource:
                product: windows
                service: sysmon
            detection:
                sel:
                    OriginalFileName: cmd.exe
                condition: sel
        """)
    ) == ['process.pe.original_file_name:"cmd.exe"']


def test_quickwit_windows_multiple_fields(quickwit_backend):
    assert quickwit_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test Multiple Fields
            status: test
            logsource:
                product: windows
                service: sysmon
            detection:
                sel:
                    EventID: 1
                    Image: '*\\powershell.exe'
                    CommandLine: '*-enc*'
                condition: sel
        """)
    ) == [
        'winlog.event_id:1 AND process.executable:"*\\\\powershell.exe" AND process.command_line:"*-enc*"'
    ]


def test_quickwit_windows_unmapped_field(quickwit_backend):
    assert quickwit_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test Unmapped Field
            status: test
            logsource:
                product: windows
                service: security
            detection:
                sel:
                    UnmappedField: some_value
                condition: sel
        """)
    ) == ['UnmappedField:"some_value"']


def test_quickwit_windows_multiple_services(quickwit_backend):
    assert quickwit_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test Multiple Services
            status: test
            logsource:
                product: windows
                service: security
            detection:
                sel_security:
                    EventID: 4624
                sel_sysmon:
                    EventID: 1
                    service: sysmon
                condition: sel_security or sel_sysmon
        """)
    ) == ['winlog.event_id:4624 OR (winlog.event_id:1 AND service:"sysmon")']


# Add more tests as needed to cover other aspects of your pipeline
