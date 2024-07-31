from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
import requests

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///order_db.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, nullable=False)
    address = db.Column(db.String(255), nullable=False)
    payment_info = db.Column(db.String(255), nullable=False)

@app.route('/checkout', methods=['POST'])
def checkout():
    data = request.get_json()
    if not data or 'user_id' not in data or 'address' not in data or 'payment_info' not in data:
        return jsonify({'error': 'Invalid data provided'}), 400

    user_id = data['user_id']
    address = data['address']
    payment_info = data['payment_info']

    try:
        # Create new order
        new_order = Order(user_id=user_id, address=address, payment_info=payment_info)
        db.session.add(new_order)
        db.session.commit()

        # Clear user's cart (implemented in cart_service)
        response = requests.delete(f'http://cart_container:5003/clear_cart/{user_id}')
        if response.status_code == 200:
            return jsonify({'message': 'Order placed successfully'}), 200
        else:
            return jsonify({'error': 'Failed to clear cart. Order not placed'}), 500
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(host="0.0.0.0", debug=True, port=5004)
