import { useEffect, useState } from "react";
const MENU_API = process.env.MENU_API;
const useRestaurantMenu = (resId) =>{
    const [resInfo, setResInfo] = useState(null);

    useEffect(()=>{
        fetchData();

    },[]);
    const fetchData = async () =>{
        const data = await fetch(MENU_API+resId);
        const json = await data.json();
        console.log(json);
        setResInfo(json.data);
    }
    return resInfo;
}

export default useRestaurantMenu;