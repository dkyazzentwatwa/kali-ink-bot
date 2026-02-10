import pytest

from core.kali_tools import KaliToolManager


@pytest.fixture
def mock_tools(monkeypatch):
    installed = {
        "nmap": "/usr/bin/nmap",
        "hydra": "/usr/bin/hydra",
        "nikto": "/usr/bin/nikto",
    }

    def _fake_which(name: str):
        return installed.get(name)

    monkeypatch.setattr("shutil.which", _fake_which)


def test_tools_status_pi_profile(mock_tools, temp_data_dir):
    manager = KaliToolManager(
        data_dir=temp_data_dir,
        package_profile="pi-headless-curated",
    )

    status = manager.get_tools_status()

    assert status["package_profile"] == "pi-headless-curated"
    assert status["required_missing"] == []
    assert "msfconsole" in status["optional_missing"]
    assert status["blocking"] is False
    assert "sudo apt install -y kali-linux-headless nmap hydra nikto" in status["install_guidance"]["pi_baseline"]


@pytest.mark.asyncio
async def test_exploit_graceful_when_optional_missing(mock_tools, temp_data_dir):
    manager = KaliToolManager(data_dir=temp_data_dir)
    result = await manager.exploit_with_msfconsole(
        target="127.0.0.1",
        exploit_module="exploit/linux/test",
        options={"RHOSTS": "127.0.0.1"},
    )

    assert result["success"] is False
    assert "msfconsole" in result["error"]
    assert "optional tool" in result["error"].lower()


@pytest.mark.asyncio
async def test_session_list_graceful_when_optional_missing(mock_tools, temp_data_dir):
    manager = KaliToolManager(data_dir=temp_data_dir)
    result = await manager.list_sessions()

    assert result["success"] is False
    assert result["sessions"] == []
    assert "msfconsole" in result["error"]
