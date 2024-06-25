from .quickwit import quickwit_pipeline
# TODO: add all pipelines that should be exposed to the user of your backend in the import statement above.

pipelines = {
    "quickwit_pipeline": quickwit_pipeline,  # TODO: adapt identifier to something approproiate
}
