// import { addItem } from "../utils/cartSlice";
// import { CDN_URL } from "../utils/constant";
// import { useDispatch } from "react-redux";
// import toast, { Toaster } from "react-hot-toast";  // ✅ import toast

// const ItemList = ({ items }) => {
//   const dispatch = useDispatch();

// const handleAddItem = (item) => {
//   dispatch(addItem(item)); // add to redux store

//   toast.success(`${item.card.info.name} added to cart 🛒`, {
//     duration: 2000,
//     position: "top-center", // ✅ show at the center top
//     style: {
//       background: "#000",   // black background
//       color: "#fff",        // white text
//       fontSize: "14px",     // text size
//       padding: "12px 20px",
//       borderRadius: "12px", // rounded corners
//       boxShadow: "0px 4px 12px rgba(0,0,0,0.3)",
//     },
//     iconTheme: {
//       primary: "#22c55e", // green icon
//       secondary: "#fff",
//     },
//   });
// };


//   return (
//     <div>
//       {items.map((item) => (
//         <div
//           className="m-0 md:m-2 p-2 border-gray-200 border-b-2 flex justify-between text-left"
//           key={item.card.info.id}
//         >
//           <div className="w-8/12">
//             <div className="py-2">
//               <span>{item.card.info.name}</span>
//               <span>
//                 {" "}
//                 - ₹{" "}
//                 {item.card.info.price
//                   ? item.card.info.price / 100
//                   : item.card.info.defaultPrice / 100}
//               </span>
//             </div>
//             <p className="text-xs sm:text-sm md:text-sm">
//               {item.card.info.description}
//             </p>
//           </div>
//           <div className="w-4/12 p-0 sm:4 md:p-4">
//             <div className="absolute">
//               <button
//                 className="p-1 sm:p-2 sm:text-sm md:p-2 text-xs bg-black text-white rounded-lg shadow-lg"
//                 onClick={() => handleAddItem(item)}
//               >
//                 Add+
//               </button>
//             </div>
//             <img
//               src={CDN_URL + item.card.info.imageId}
//               className="w-full"
//               alt={item.card.info.name}
//             />
//           </div>
//         </div>
//       ))}

//       {/* ✅ Toast container (needed once in the app, can also be in App.js) */}
//       <Toaster />
//     </div>
//   );
// };

// export default ItemList;


import { addItem } from "../utils/cartSlice";
const CDN_URL = process.env.CDN_URL;
import {useDispatch} from "react-redux";

const ItemList = ({items}) =>{
    const dispatch = useDispatch();
    const handleAddItem = (item)=>{
           dispatch(addItem(item));
    }

    return (
        <div>
            {
                items.map((item) => 
                <div className = "m-0 md:m-2 p-2 border-gray-200 border-b-2 flex justify-between text-left" key ={item.card.info.id}>
                    <div className="w-8/12">
                        <div className="py-2">
                        <span >{item.card.info.name}</span>
                        <span> - ₹ {" "}{item.card.info.price? item.card.info.price/100: item.card.info.defaultPrice /100}</span>
                        </div>
                        <p className="text-xs sm:text-sm md:text-sm">{item.card.info.description }</p>
                    </div>
                    <div className="w-4/12 p-0 sm:4 md:p-4">
                        <div className="absolute">
                            <button className="p-1 sm:p-2 sm:text-sm md:p-2 text-xs   bg-black text-white rounded-lg shadow-lg" onClick={()=>handleAddItem(item)}>Add+</button>
                        </div>
                        <img src = {CDN_URL+item.card.info.imageId} className="w-full" />
                    </div>
                </div>)
            }
        </div>
    );
}

export default ItemList;