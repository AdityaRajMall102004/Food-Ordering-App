import { useDispatch } from "react-redux";
import { CDN_URL } from "../utils/constant";
import { removeItem } from "../utils/cartSlice";

const cartItemList = ({items})=>{
    const dispatch = useDispatch();
    const handleRemoveItem = (item)=>{
           dispatch(removeItem(item));
    }

    return (
        <div>
            {
                items.map((item) => 
                <div className = "m-2 p-2 border-gray-200 border-b-2 flex justify-between text-left" key ={item.card.info.id}>
                    <div className="w-7/12 sm:w-8/12 md:w-8/12">
                        <div className="py-2">
                        <span >{item.card.info.name}</span>
                        <span> - ₹ {" "}{item.card.info.price? item.card.info.price/100: item.card.info.defaultPrice /100}</span>
                        </div>
                        <p className="text-xs md:text-sm">{item.card.info.description }</p>
                    </div>
                    <div className="w-5/12 sm:w-4/12 md:w-4/12 p-1 md:p-4">
                        <div className="absolute">
                            <button className=" p-1 text-sm md:text-sm md:p-2  bg-black text-white rounded-lg shadow-lg" onClick={()=>handleRemoveItem()}>Remove</button>
                        </div>
                        <img src = {CDN_URL+item.card.info.imageId} className="w-ful "/>
                    </div>
                </div>)
            }
        </div>
    );
}

export default cartItemList;