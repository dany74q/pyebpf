import types


def assert_type(expected_type, **kwargs):
    # type: (types.TypeType|types.TupleType[types.TypeType], **types.ObjectType) -> None

    for k, v in kwargs.iteritems():
        assert isinstance(v, expected_type), 'Expected {} to be of type {}, actually got {}'.format(k,
                                                                                                    expected_type,
                                                                                                    type(v))
