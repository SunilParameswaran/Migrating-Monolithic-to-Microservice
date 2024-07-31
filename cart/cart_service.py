# cart_service.py
from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///cart_db1.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

class CartItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    price = db.Column(db.Integer, nullable=False)
    product_name = db.Column(db.String(100), nullable=False)
    user_id = db.Column(db.Integer, nullable=False)
    quantity = db.Column(db.Integer, nullable=False, default=1)

@app.route('/add_to_cart', methods=['POST'])
def add_to_cart():
    data = request.get_json()
    
    user_id = data['user_id']
    
    name = data['product_name']

    price=data['price']

    # Add item to cart
    cart_item = CartItem(product_name=name, user_id=user_id,price = price)
    db.session.add(cart_item)
    db.session.commit()

    return jsonify({'message': 'Item added to cart successfully'})

@app.route('/clear_cart/<int:user_id>', methods=['DELETE'])
def clear_cart(user_id):
    try:
        # Retrieve all cart items for the specified user_id and delete them
        cart_items = CartItem.query.filter_by(user_id=user_id).all()
        for item in cart_items:
            db.session.delete(item)
        db.session.commit()

        return jsonify({'message': f'Cart cleared for user {user_id}'}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/view_cart/<int:user_id>', methods=['GET'])
def view_cart(user_id):
    cart_items = CartItem.query.filter_by(user_id=user_id).all()
    cart_data = []
    total = 0
    for item in cart_items:
        item_data = {
            'product_name': item.product_name,
            'quantity': item.quantity,
            'price': item.price
        }
        cart_data.append(item_data)
        total += item.price * item.quantity
    print(cart_data)
    # Return JSON response including cart items and total
    response_data = {'cart_items': cart_data, 'total': total}
    #cart_data = [{'product_name': item.product_name, 'quantity': item.quantity, 'total':sum(item.price * item.quantity for item in cart_items)} for item in cart_items]
    return jsonify(response_data)


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(host="0.0.0.0", debug=True, port=5003)
