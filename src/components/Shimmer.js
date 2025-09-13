const Shimmer = () =>{
    return (
        <>
        <div className="flex border items-center justify-center py-6">
          <h2 className="border w-96 h-7 p-5 rounded-md border-gray-300"></h2>
          <h2 className="border w-14 h-7 p-5 rounded-md ml-3 bg-gray-200"></h2>
        </div>
          <div className="flex flex-wrap my-1 rounded-md justify-center">
            {Array(16)
              .fill("")
              .map((e, index) => (
                <div key={index} className="border  w-72 m-10 min-h-[330px] shadow-xl rounded-md">
                  <h1 className="border w-72 h-44 bg-gray-200 rounded-tl-md rounded-tr-md" ></h1>
                  <h1 className=" w-48 h-8 ml-3 rounded-md bg-gray-200 my-3"></h1>
                  <h1 className=" w-64 h-8 ml-4 rounded-md bg-gray-200 my-3"></h1>
                  <h1 className=" w-28 h-6 ml-4 rounded-md bg-gray-200 my-3"></h1>
                </div>
              ))}
          </div>
        </>
      );
}

export default Shimmer;