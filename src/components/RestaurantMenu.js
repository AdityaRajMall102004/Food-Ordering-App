import { useEffect, useState } from "react";
import Shimmer from "./Shimmer";
import { useParams } from "react-router-dom";
import useRestaurantMenu from "../utils/useRestaurantMenu";
import RestaurantCategory from "./RestaurantCategory";
import { CDN_URL } from "../utils/constant";

const RestaurantMenu = () =>{
    
    const {resId} = useParams();
    const resInfo = useRestaurantMenu(resId);
    console.log(resInfo);
    const [showIndex, setShowIndex] = useState(null);
    if(resInfo==null)
      return <Shimmer/>
    const {name,cuisines,costForTwoMessage,avgRating,sla,cloudinaryImageId} = resInfo?.cards[2]?.card?.card?.info;

    
    const categories = resInfo?.cards[4]?.groupedCard?.cardGroupMap?.REGULAR?.cards.filter((c) =>c?.card?.card?.["@type"]=="type.googleapis.com/swiggy.presentation.food.v2.ItemCategory");
    return (
        
        <div className="text-center">
            <div className="restaurant-summary flex justify-center items-center p-2 md:p-5  bg-gray-900  w-full ">
                <img className="rounded-md w-32 sm:w-44 md:w-64 h-32 sm:h-40 md:h-52" src={CDN_URL + cloudinaryImageId}alt={name}/>
                <div className="">
                    <h2 className="text-lg sm:text-lg md:text-3xl font-bold pl-10 text-white">
                        {name}
                    </h2>
                    <p className="font-semibold mt-2 pl-10 text-gray-300">
                        {cuisines?.join(", ")}
                    </p>
                    <div className="font-bold text-white flex pl-2 md:pl-10 mt-2">
                        <div className=" px-1 py-1 pr-2 bg-green-900  rounded-md text-sm">
                            ⭐ {avgRating}{" "}
                        </div>
                    <div className="px-3">|</div>
                    <div className="text-sm"> ⏱️{sla.slaString} </div>
                    <div className="px-3">|</div>
                    <div className="text-sm">{costForTwoMessage}</div>
                </div>
                </div>
            </div>
            {/* <h1 className="font-bold text-2xl my-6 ">{name}</h1>
            <p className="font-bold text-lg">{cuisines.join(",")} - {costForTwoMessage}</p> */}
            {
               categories && categories.map((category,index)=>
                <RestaurantCategory key = {category?.card?.card?.title} data = {category?.card?.card} showItems = {index===showIndex?true:false} setShowIndex = {()=>setShowIndex(index)}/>)
            }
        </div>
        
    );
}

export default RestaurantMenu;