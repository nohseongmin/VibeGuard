"""데스크톱 앱의 설정·검사 기록 저장소 테스트.

APPDATA 를 임시 폴더로 바꿔 실제 사용자 데이터를 건드리지 않는다.
"""

import time

import pytest

from vibeguard import appdata


@pytest.fixture
def isolated(tmp_path, monkeypatch):
    monkeypatch.setenv("APPDATA", str(tmp_path))
    return tmp_path


def test_app_dir_created(isolated):
    path = appdata.app_dir()
    assert path.startswith(str(isolated))
    assert path.endswith("VibeGuard")


def test_defaults_when_no_file(isolated):
    assert appdata.load_settings() == appdata.DEFAULT_SETTINGS


def test_save_and_load_settings(isolated):
    settings = appdata.load_settings()
    settings["online_lookup"] = False
    settings["min_severity"] = "HIGH"
    settings["exclude"] = ["vendor", "tmp"]
    settings["history_limit"] = 7
    appdata.save_settings(settings)

    loaded = appdata.load_settings()
    assert loaded["online_lookup"] is False
    assert loaded["min_severity"] == "HIGH"
    assert loaded["exclude"] == ["vendor", "tmp"]
    assert loaded["history_limit"] == 7


def test_broken_settings_file_falls_back(isolated):
    path = appdata.app_dir()
    with open(path + "/settings.json", "w", encoding="utf-8") as fh:
        fh.write("{ this is not json")
    # 깨진 파일이어도 앱이 뜨도록 기본값으로 돌아간다
    assert appdata.load_settings() == appdata.DEFAULT_SETTINGS


def test_invalid_values_are_corrected(isolated):
    appdata.save_settings({"min_severity": "ZZZ", "exclude": "notalist",
                           "history_limit": "abc", "online_lookup": True})
    loaded = appdata.load_settings()
    assert loaded["min_severity"] == appdata.DEFAULT_SETTINGS["min_severity"]
    assert loaded["exclude"] == []
    assert loaded["history_limit"] == appdata.DEFAULT_SETTINGS["history_limit"]


def _payload(path, score=50):
    return {"path": path, "score": score, "grade": "C", "verdict": "보통",
            "files_scanned": 3, "total": 2, "counts": {}, "findings": []}


def test_save_scan_and_list_newest_first(isolated):
    appdata.save_scan(_payload("/first"))
    time.sleep(0.01)
    appdata.save_scan(_payload("/second"))

    scans = appdata.list_scans()
    assert len(scans) == 2
    assert scans[0]["path"] == "/second"     # 최신이 맨 위
    assert scans[1]["path"] == "/first"
    assert scans[0]["scanned_at"] >= scans[1]["scanned_at"]


def test_history_limit_trims_oldest(isolated):
    for i in range(5):
        appdata.save_scan(_payload("/p%d" % i), limit=3)
        time.sleep(0.01)
    scans = appdata.list_scans()
    assert len(scans) == 3
    assert scans[0]["path"] == "/p4"          # 최신은 남고 오래된 것부터 지워진다


def test_load_scan_roundtrip(isolated):
    out = appdata.save_scan(_payload("/round", score=88))
    data = appdata.load_scan(out)
    assert data["path"] == "/round"
    assert data["score"] == 88
    assert "scanned_at" in data


def test_clear_history(isolated):
    appdata.save_scan(_payload("/a"))
    appdata.save_scan(_payload("/b"))
    assert appdata.clear_history() == 2
    assert appdata.list_scans() == []
