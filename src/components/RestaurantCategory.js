import { useState } from "react";
import ItemList from "./ItemList";


const RestaurantCategory = ({data,showItems,setShowIndex}) =>{
    
    const handleClick = ()=>{
        setShowIndex();
    }
    return (
        <div>
            <div className="w-10/12/12 sm:w-8/12 md:w-6/12 mx-auto my-4  bg-gray-50 shadow-lg p-4">
                <div className=" flex justify-between cursor-pointer" onClick={handleClick}>
                    <span className="font-bold text-sm sm:text-lg md:text-lg">{data.title} ({data.itemCards.length})</span>
                    <span className="font-bold text-sm sm:text-lg md:text-lg">⬇</span>
                </div>
                   {showItems && <ItemList items = {data.itemCards}/>}
            
            </div>
        </div>
    );
}

export default RestaurantCategory;