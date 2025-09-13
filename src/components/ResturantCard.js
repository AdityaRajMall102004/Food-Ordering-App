import { CDN_URL } from "../utils/constant";
import { useContext } from "react";


const ResturantCard = (props) =>{
    const {resData} = props;
   
    const {cloudinaryImageId,name,cuisines,avgRating,costForTwo,sla,areaName} = resData?.info;
    
    return (
      <div className="border w-[14rem] md:w-64 m-5 md:m-10 min-h-[330px] p-3 shadow-xl rounded-md transition-transform hover:scale-105">
        <img
          className="w-60 md:w-72 h-48 shadow-md rounded-md"
          src={CDN_URL + cloudinaryImageId}
        />
        <h2 className="text-xl font-medium ">{name}</h2>
        <h3 className="font-light text-sm">{cuisines.join(", ")}</h3>
        <h5 className="font-light text-sm">{areaName}</h5>
        <div className=" flex justify-between items-center md:pr-3">
          <h5 className="card-tag flex justify-center border text-sm w-12 mt-2 text-white font-semibold bg-red-900 px-7 py-1 rounded-md">
            {" "}
            ⭐{avgRating}
          </h5>
          <h3 className="font-semibold text-xs md:text-sm mt-2">
            • {costForTwo ?? "₹200 for two"}
          </h3>
          <h3 className="font-semibold text-xs md:text-sm  mt-2">
            • {sla?.lastMileTravelString ?? "2.0 km"}
          </h3>
        </div>
      </div>
    );
  };

  export default ResturantCard;
  
 