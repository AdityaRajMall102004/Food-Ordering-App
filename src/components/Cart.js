import {useSelector, useDispatch} from "react-redux"
import { clearCart } from "../utils/cartSlice";
import CartItemList from "./CartItemList";

const Cart = () =>{
    const dispatch = useDispatch();
    const handleClearCart = ()=>{
        dispatch(clearCart());
    }
    const cartItems = useSelector((store)=> store.cart.items);
    return (
        <div className="text-center m-0 sm:m-2 md:m-4 p-4">
            <h1 className="font-bold text-2xl">Cart</h1>
            <div className="w-10/12 md:w-6/12 m-auto">
                <button 
                    className="p-2 m-2 bg-black text-white rounded-lg" 
                    onClick={handleClearCart}
                >
                    Clear Cart
                </button>

                {cartItems.length === 0 && (
                    <h1>Cart is empty. Add items to the Cart!</h1>
                )}

                <CartItemList items={cartItems} />
                
                {cartItems.length !== 0 && (
                    <button 
                        className="p-2 m-2 bg-green-600 text-white rounded-lg hover:bg-green-700"
                        onClick={()=>{ alert("Order placed successfully 🚀");
                            dispatch(clearCart());
                         }}
                    >
                        Order
                    </button>
                )}
            </div>
        </div>
    );
}

export default Cart;
