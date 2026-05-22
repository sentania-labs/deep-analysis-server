"""Operator-invoked maintenance scripts for the parser service.

These scripts are CLI entry points that the operator runs by hand
inside the parser container — they are NOT auto-invoked on deploy.

Each script lives in its own module and exposes a ``main()`` callable
so it can be run via ``python -m parser_service.scripts.<name>``.
"""
