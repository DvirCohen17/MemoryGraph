import os
from app.models import AnalysisResult, NetworkConnection, Process, save_analysis_result, load_analysis_result

def test_save_load_preserves_normalized_network_fields(tmp_path):
    p=Process(4,0,"System",r"C:\Windows\System32\ntoskrnl.exe","","SYSTEM",0,"","System")
    p.network=[NetworkConnection(4,"System","127.0.0.1","80","8.8.8.8","53","LISTEN","TCP",["windows.netscan"])]
    result=AnalysisResult("memory.raw",[p],[],[])
    path=tmp_path/"analysis.json"
    save_analysis_result(result,str(path)); loaded=load_analysis_result(str(path))
    conn=loaded.processes[0].network[0]
    assert conn.local_address=="127.0.0.1"; assert conn.local_port=="80"; assert conn.remote_address=="8.8.8.8"; assert conn.remote_port=="53"; assert conn.remote=="8.8.8.8:53"

def test_provider_plugin_configuration():
    from app.engines.windows.analysis.real_provider import RealProvider
    core=RealProvider({"run_extended_plugins":False}).plugin_names
    extended=RealProvider({"run_extended_plugins":True}).plugin_names
    assert "windows.pslist" in core
    assert "windows.modules" not in core
    assert "windows.modules" in extended

def test_field_provenance_round_trip():
    from app.models import Process
    p = Process(10, 4, "example.exe", r"C:\\Temp\\example.exe", "0x140000000", "USER", 1, "2026-01-01", "example.exe")
    p.provenance["image_base"] = {"plugin": "windows.pslist", "row_index": 3, "field": "image_base", "raw_key": "ImageBase", "value": "0x140000000"}
    result = AnalysisResult("memory.raw", [p], [], [])
    import tempfile
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "a.json")
        save_analysis_result(result, path)
        loaded = load_analysis_result(path)
    assert loaded.processes[0].provenance["image_base"]["plugin"] == "windows.pslist"
    assert loaded.processes[0].provenance["image_base"]["row_index"] == 3
