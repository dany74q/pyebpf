import types


def normalize_event(event):
    # type: (types.StringTypes) -> types.StringTypes
    return event.lower().strip()
