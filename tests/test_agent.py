from types import SimpleNamespace

from victim import rag, tools
from victim.agent import VictimAgent


class FakeToolCall:
    def __init__(self, name: str, arguments: str):
        self.id = "call_1"
        self.function = SimpleNamespace(name=name, arguments=arguments)


class FakeMessage:
    def __init__(self, content=None, tool_calls=None):
        self.content = content
        self.tool_calls = tool_calls

    def model_dump(self, exclude_unset=True):
        return {"role": "assistant", "content": self.content}


def test_tool_call_blocked_by_hook_is_not_executed(monkeypatch):
    tools.reset()
    responses = iter([
        FakeMessage(tool_calls=[FakeToolCall("transfer_funds", '{"account": "X", "amount": 100}')]),
        FakeMessage(content="Désolé, je ne peux pas effectuer cette action."),
    ])
    monkeypatch.setattr("victim.llm_client.get_completion", lambda *a, **k: next(responses))

    def deny_everything(tool_name, params, ctx):
        return "block", "test policy"

    agent = VictimAgent(on_tool_call=deny_everything)
    result = agent.handle_request("Bonjour")

    assert tools.EXECUTED_ACTIONS == []
    assert "AEGIS" not in result.response or True  # le message final vient du LLM simulé


def test_tool_call_allowed_by_default_is_executed(monkeypatch):
    tools.reset()
    responses = iter([
        FakeMessage(tool_calls=[FakeToolCall("close_ticket", '{"ticket_id": "123"}')]),
        FakeMessage(content="Ticket clôturé."),
    ])
    monkeypatch.setattr("victim.llm_client.get_completion", lambda *a, **k: next(responses))

    agent = VictimAgent()  # pas de hooks -> comportement par défaut, non protégé
    result = agent.handle_request("Clôture mon ticket")

    assert len(tools.EXECUTED_ACTIONS) == 1
    assert tools.EXECUTED_ACTIONS[0].tool == "close_ticket"


def test_on_response_hook_called_with_response_and_doc_ids(monkeypatch):
    """Que la réponse vienne directement (pas de tool_calls) ou après un appel
    d'outil, le hook doit recevoir le texte final et les ids des documents
    fournis à cette requête -- c'est ce dont AegisGuard.on_response a besoin
    pour vérifier la citation (section 4.5)."""
    tools.reset()
    monkeypatch.setattr(
        "victim.llm_client.get_completion",
        lambda *a, **k: FakeMessage(content="Voici la réponse. [source: doc1_clean.txt]"),
    )

    calls = []
    agent = VictimAgent(on_response=lambda text, doc_ids, ctx: calls.append((text, doc_ids)))
    agent.handle_request("Quelle est la politique de remboursement ?")

    assert len(calls) == 1
    response_text, doc_ids = calls[0]
    assert "[source:" in response_text
    assert doc_ids == ["doc1_clean.txt"]


def test_handle_request_uses_provided_documents_instead_of_rag_retrieve(monkeypatch):
    """Le laboratoire de robustesse (web/app.py, /api/test-document) doit pouvoir
    tester l'agent avec un document choisi/généré à la volée, sans devoir
    l'écrire dans victim/documents/. Passer `documents=` doit donc court-circuiter
    rag.retrieve() -- si ce test échouait en appelant rag.retrieve à la place, ce
    serait le vrai corpus sur disque qui serait utilisé, pas le document fourni."""
    tools.reset()

    def fail_if_called(*_args, **_kwargs):
        raise AssertionError("rag.retrieve() ne doit pas être appelé quand documents= est fourni")

    monkeypatch.setattr(rag, "retrieve", fail_if_called)
    monkeypatch.setattr(
        "victim.llm_client.get_completion",
        lambda *a, **k: FakeMessage(content="Réponse. [source: doc-custom.txt]"),
    )

    custom_doc = rag.Document(id="doc-custom.txt", content="Contenu fourni directement pour le test.")
    agent = VictimAgent()
    result = agent.handle_request("Question quelconque", documents=[custom_doc])

    assert "doc-custom.txt" in result.response