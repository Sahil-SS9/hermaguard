def handler(event):
    try:
        return do_work(event)
    except Exception as e:
        return {"statusCode": 500, "body": str(e)}
