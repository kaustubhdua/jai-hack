def test_uvicorn_is_available_for_the_documented_local_api_command():
    import uvicorn

    assert callable(uvicorn.run)
