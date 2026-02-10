from mcp_servers.kali import KaliMCPServer


def test_pentest_tools_status_reports_profile_and_guidance(temp_data_dir):
    server = KaliMCPServer(
        data_dir=temp_data_dir,
        pentest_config={
            "package_profile": "pi-headless-curated",
            "required_tools": ["nmap", "hydra", "nikto"],
            "optional_tools": ["msfconsole", "sqlmap", "aircrack-ng"],
        },
    )

    response = server.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "pentest_tools_status",
                "arguments": {},
            },
        }
    )

    assert "result" in response
    content = response["result"]["content"][0]["text"]
    assert "pi-headless-curated" in content
    assert "kali-linux-headless" in content


def test_mcp_lists_modular_profile_tools(temp_data_dir):
    server = KaliMCPServer(data_dir=temp_data_dir)
    response = server.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/list",
            "params": {},
        }
    )

    names = {tool["name"] for tool in response["result"]["tools"]}
    assert "pentest_profiles_list" in names
    assert "pentest_profile_status" in names
    assert "pentest_profile_install_command" in names
