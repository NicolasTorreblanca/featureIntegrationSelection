import inspect
from pipeline import tune


def test_ee_ranges_match_thesis_table_3_5():
    src = inspect.getsource(tune._objective_ee)
    # Tabla 3.5: contamination 0.01-0.1 ; support_fraction 0.1-1.0
    assert 'suggest_float("contamination", 0.01, 0.1)' in src
    assert 'suggest_float("support_fraction", 0.1, 1.0)' in src
