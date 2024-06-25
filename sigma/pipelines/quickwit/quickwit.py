from sigma.pipelines.common import logsource_windows, windows_logsource_mapping
from sigma.pipelines.base import Pipeline
from sigma.processing.transformations import (
    FieldMappingTransformation,
)
from sigma.processing.pipeline import (
    ProcessingItem,
    ProcessingPipeline,
)

# TODO: the following code is just an example extend/adapt as required.
# See https://sigmahq-pysigma.readthedocs.io/en/latest/Processing_Pipelines.html for further documentation.


@Pipeline
def quickwit_windows_pipeline() -> ProcessingPipeline:
    return ProcessingPipeline(
        name="Quickwit example pipeline",
        allowed_backends=frozenset(),  # Set of identifiers of backends (from the backends mapping) that are allowed to use this processing pipeline. This can be used by frontends like Sigma CLI to warn the user about inappropriate usage.
        priority=20,  # The priority defines the order pipelines are applied. See documentation for common values.
        items=[
            ProcessingItem(  # This is an example for processing items generated from the mapping above.
                identifier=f"quickwit_windows_{service}",
                transformation=FieldMappingTransformation(
                    {
                        "EventID": "winlog.event_id",
                        "Image": "process.executable",
                        "CommandLine": "process.command_line",
                        "OriginalFileName": "process.pe.original_file_name",
                    }
                ),
                rule_conditions=[logsource_windows(service)],
            )
            for service, source in windows_logsource_mapping.items()
        ],
    )
