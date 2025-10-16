from app import app

with app.test_client() as c:
    resp = c.get('/health')
    print('STATUS', resp.status_code)
    print(resp.get_data(as_text=True))
