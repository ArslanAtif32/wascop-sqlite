import os
import time

from lib.DB import DB
from lib import Utils as Utility


class ControllerRequestRecord:
    def __init__(self):
        self.db = DB()
        self.timestamp = str(int(time.time()))

    def query_record_fusion(self, _host, _content_type="json", _method="get"):
        sql = (
            "SELECT DISTINCT a.url AS origin_url, a.referer, b.url AS gen_url, "
            "b.response_hash, b.response FROM request_record a "
            "LEFT JOIN request_record_second b ON a.url=b.origin_url "
            "WHERE a.host=? AND a.content_type=? AND a.method=? "
            "AND a.get_sensitive!='' AND b.url!='' AND b.response NOT IN ('[]','')"
        )
        return self.db.query(sql, (_host, _content_type, _method))

    def query_record_second_analysis(self, _host):
        sql = (
            "SELECT host,method,origin_url,referer,url,gen_params,response_hash,"
            "response_sensitive,response_exists_sensitive,response "
            "FROM request_record_second GROUP BY response_hash "
            "HAVING response_exists_sensitive>0 AND host LIKE ? "
            "ORDER BY referer DESC, origin_url DESC, url DESC"
        )
        return Utility.build_tree(self.db.query(sql, ("%" + _host + "%",)))

    def query_record_second(self, where="1=1", fields="*", params=()):
        return self.db.query_request_record_second(where=where, fields=fields, params=params)

    def add_request_record_second(self, _data):
        hash_val = Utility.md5(_data["method"] + _data["gen_params"] + _data["response"])
        record = {
            "host": _data["host"],
            "hash": hash_val,
            "method": _data["method"],
            "content_type": _data["content_type"],
            "referer": _data["referer"],
            "origin_url": _data["origin_url"],
            "url": _data["url"],
            "response": _data["response"],
            "response_exists_sensitive": _data["response_exists_sensitive"],
            "response_sensitive": _data["response_sensitive"],
            "response_hash": Utility.md5(_data["response"]),
            "gen_params": _data["gen_params"],
            "create_time": self.timestamp,
        }
        record_check = self.query_record_second("hash=?", "id", (hash_val,))
        if not record_check:
            try:
                self.db.add_request_record_second(values=record)
            except Exception as e:
                self._log_insert_error(_data, e, "error.txt")

    def query_record(self, where="1=1", fields="*", params=()):
        return self.db.query_request_record(where=where, fields=fields, params=params)

    def add_record(self, _data):
        hash_val = Utility.md5(_data["method"] + _data["url"] + _data["response"])
        record = {
            "flow_id": _data["flow_id"],
            "host": _data["host"],
            "port": _data["port"],
            "hash": hash_val,
            "method": _data["method"],
            "url": _data["url"],
            "referer": _data["referer"],
            "content_type": _data["content_type"],
            "response": _data["response"],
            "response_exists_sensitive": _data["response_exists_sensitive"],
            "response_sensitive": _data["response_sensitive"],
            "path": _data["path"],
            "path_exist_sensitive": _data["path_exist_sensitive"],
            "path_sensitive": _data["path_sensitive"],
            "get_params": _data["get_params"],
            "get_exist_sensitive": _data["get_exist_sensitive"],
            "get_sensitive": _data["get_sensitive"],
            "post_params": _data["post_params"],
            "post_exist_sensitive": _data["post_exist_sensitive"],
            "post_sensitive": _data["post_sensitive"],
            "create_time": self.timestamp,
        }
        record_check = self.query_record("hash=?", "id", (hash_val,))
        if not record_check:
            try:
                self.db.add_request_record(values=record)
            except Exception as e:
                self._log_insert_error(_data, e, "second_error.txt")

    @staticmethod
    def _log_insert_error(data, error, filename):
        host = str(data.get("host", "unknown")).replace("/", "_").replace("\\\\", "_")
        dir_path = os.path.join(".", "mitmproxy", host, "error")
        os.makedirs(dir_path, exist_ok=True)
        path = str(data.get("url", "unknown")).split("/")[-1].split("?")[0].replace(".", "_")
        file_path = os.path.join(dir_path, path + "_" + filename)
        log_data = {
            "exception": str(error),
            "url": data.get("url", ""),
            "create_time": str(int(time.time())),
        }
        with open(file_path, "a", encoding="utf-8") as f:
            f.write(Utility.dict2json(log_data))
