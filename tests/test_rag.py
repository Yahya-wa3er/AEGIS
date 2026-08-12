# tests/test_rag.py
from victim.rag import retrieve


def test_retrieve_finds_relevant_document_for_support_ticket_query():
    results = retrieve("ticket 48291", top_k=1)
    assert len(results) == 1
    assert "48291" in results[0].content


def test_retrieve_returns_top_k_documents():
    results = retrieve("remboursement virement", top_k=2)
    assert len(results) <= 2