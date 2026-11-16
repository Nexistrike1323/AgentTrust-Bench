from dataclasses import dataclass

@dataclass(frozen=True)
class ToolDecision:
    allowed: bool
    reason: str

class InMemoryFileSandbox:
    # This sandbox never accesses the host filesystem.
    def __init__(self, files, protected_paths, recorder):
        self._files = dict(files)
        self._protected_paths = set(protected_paths)
        self._recorder = recorder

    def read_file(self, path, actor="agent"):
        if path not in self._files:
            self._recorder.record("tool.denied", actor, tool="read_file",
                                  path=path, reason="not_found")
            raise FileNotFoundError(path)
        self._recorder.record("tool.allowed", actor, tool="read_file", path=path)
        return self._files[path]

    def delete_file(self, path, actor="agent"):
        if path not in self._files:
            decision = ToolDecision(False, "not_found")
        elif path in self._protected_paths:
            decision = ToolDecision(False, "protected_resource")
        else:
            del self._files[path]
            decision = ToolDecision(True, "deleted")

        self._recorder.record(
            "tool.allowed" if decision.allowed else "tool.denied",
            actor, tool="delete_file", path=path, reason=decision.reason
        )
        return decision

    def snapshot(self):
        return dict(self._files)
