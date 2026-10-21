import pytest

from app.services.detection.evaluation import latency_minutes, operating_point, task_ranking, task_subset


def rec(label, start="2022-01-24T03:00:00Z"):
    return {"label": label, "window_start": start}


RECORDS = [
    rec("incident", "2022-01-24T03:05:00Z"),
    rec("incident", "2022-01-24T03:00:00Z"),
    rec("exfiltration"),
    rec("background"),
    rec("background"),
    rec("background"),
]


def test_task_subset_keeps_positives_and_background_only():
    assert task_subset(RECORDS, "incident") == [0, 1, 3, 4, 5]
    assert task_subset(RECORDS, "exfiltration") == [2, 3, 4, 5]


def test_operating_point_counts_and_rates():
    flags = [True, False, True, True, False, False]
    op = operating_point(RECORDS, flags, days=0.5, positive="incident")
    assert op["positive_windows_flagged"] == 1 and op["positive_windows_total"] == 2
    assert op["recall"] == 0.5 and op["precision"] == 0.5
    assert op["false_alarm_windows"] == 1
    assert op["alerts_on_excluded_windows"] == {"exfiltration": 1}     # another attack class: not a false alarm
    assert op["alerts_per_day"] == 6.0 and op["false_alarms_per_day"] == 2.0
    assert op["detected"] is True and op["first_flagged_positive_window"] == "2022-01-24T03:05:00Z"


def test_operating_point_with_no_alerts():
    op = operating_point(RECORDS, [False] * 6, days=1.0, positive="incident")
    assert op["precision"] is None and op["recall"] == 0.0 and op["detected"] is False
    assert op["first_flagged_positive_window"] is None and op["alerts_per_day"] == 0.0


def test_operating_point_needs_one_flag_per_record():
    with pytest.raises(ValueError, match="one flag per record"):
        operating_point(RECORDS, [True], days=1.0, positive="incident")


def test_task_ranking_ignores_excluded_labels():
    # the exfiltration window has the highest score; for the incident task it must not count
    scores = [0.9, 0.8, 1.0, 0.1, 0.2, 0.3]
    assert task_ranking(RECORDS, scores, "incident")["roc_auc"] == 1.0
    exfil = task_ranking(RECORDS, scores, "exfiltration")
    assert exfil["roc_auc"] == 1.0 and exfil["positives"] == 1 and exfil["n"] == 4


def test_task_ranking_with_one_class_returns_none():
    only_background = [rec("background"), rec("background")]
    assert task_ranking(only_background, [0.1, 0.2], "incident")["roc_auc"] is None


def test_latency_counts_to_the_end_of_the_flagged_window():
    assert latency_minutes("2022-01-24T03:00:00Z", "2022-01-24T03:55:00Z", 300) == 60.0
    assert latency_minutes("2022-01-24T03:00:00Z", "2022-01-24T03:00:00Z", 300) == 5.0
    assert latency_minutes("2022-01-24T03:00:00Z", None, 300) is None
