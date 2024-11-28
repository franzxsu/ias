from flask import Blueprint, jsonify

bp = Blueprint('api', __name__)

@bp.route('/example-endpoint', methods=['GET'])
def example():
    return jsonify({"message": "hello test"})

@bp.route('/data', methods=['POST'])
def post_data():
    data = request.json
    return jsonify({"received_data": data}), 201