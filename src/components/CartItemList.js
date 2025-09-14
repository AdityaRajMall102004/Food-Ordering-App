import { useDispatch } from "react-redux";
const CDN_URL = process.env.CDN_URL;
import { removeItem } from "../utils/cartSlice";
const CartItemList = ({ items }) => {
  const dispatch = useDispatch();

  const handleRemoveItem = (item) => {
    dispatch(removeItem(item));
  };

  // Calculate total price
  const totalPrice = items.reduce((acc, item) => {
    const price = item.card.info.price
      ? item.card.info.price / 100
      : item.card.info.defaultPrice / 100;
    return acc + price * item.quantity;
  }, 0);

  return (
    <div>
      {items.map((item) => (
        <div
          className="m-2 p-2 border-gray-200 border-b-2 flex justify-between text-left"
          key={item.card.info.id}
        >
          <div className="w-7/12 sm:w-8/12 md:w-8/12">
            <div className="py-2">
              <span>{item.card.info.name}</span>
              <span>
                {" "}
                - ₹{" "}
                {(item.card.info.price
                  ? item.card.info.price / 100
                  : item.card.info.defaultPrice / 100) * item.quantity}
              </span>
            </div>
            <p className="text-xs md:text-sm">
              {item.card.info.description}
            </p>
          </div>
          <div className="w-5/12 sm:w-4/12 md:w-4/12 p-1 md:p-4 relative">
            {/* ✅ Quantity badge */}
            {item.quantity > 1 && (
              <span className="absolute top-0 right-0 bg-red-600 text-white text-xs px-2 py-1 rounded-full">
                {item.quantity}
              </span>
            )}
            <div className="absolute">
              <button
                className="p-1 text-sm md:text-sm md:p-2 bg-black text-white rounded-lg shadow-lg"
                onClick={() => handleRemoveItem(item)}
              >
                Remove
              </button>
            </div>
            <img
              src={CDN_URL + item.card.info.imageId}
              alt={item.card.info.name}
              className="w-full"
            />
          </div>
        </div>
      ))}

      {/* ✅ Show total only if cart not empty */}
      {items.length > 0 && (
        <h2 className="font-bold text-lg text-right p-4">
          Total: ₹ {totalPrice}
        </h2>
      )}
    </div>
  );
};

export default CartItemList;
