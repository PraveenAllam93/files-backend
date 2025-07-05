from importlib import import_module

router_modules = [
    import_module(".endpoint", package=__name__),
    import_module(".quarantine_file_check", package=__name__)
]