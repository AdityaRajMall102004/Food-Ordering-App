import { useState } from "react";


const useOnlineStatus = () =>{
    const [OnlineStatus, setOnlineStatus] = useState(true);

    window.addEventListener("online", ()=>{
        setOnlineStatus(true);
    });
    window.addEventListener("offline", ()=>{
        setOnlineStatus(false);
    });
    return OnlineStatus;
}

export default useOnlineStatus;