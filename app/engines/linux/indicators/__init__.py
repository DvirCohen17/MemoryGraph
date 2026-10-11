"""Linux engine, indicators half: the investigation rules (indications) for Linux images. Skeleton: see ``app/engines/linux/__init__.py``.

Shared building blocks, already finished and OS-independent (``app/analysis/indicators``): ``IndicatorRule`` (every rule is a subclass whose ``evaluate(result)`` returns
``Indication`` objects made with ``self.make(...)``), ``scoring`` (severity ranks and scores), ``correlation`` (several kinds of evidence on one process) and
``corroboration`` (a High finding that rests on one plugin is Medium until a second plugin agrees: list the Linux rules that need it in ``SINGLE_SOURCE_RULES`` there).
"""
