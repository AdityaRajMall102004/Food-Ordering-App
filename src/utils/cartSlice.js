import { createSlice } from "@reduxjs/toolkit";

const cartSlice = createSlice({
  name: "cart",
  initialState: {
    items: [],
  },
  reducers: {
    addItem: (state, action) => {
      const newItem = action.payload;
      const existingItem = state.items.find(
        (item) => item.card.info.id === newItem.card.info.id
      );

      if (existingItem) {
        existingItem.quantity += 1; // increase qty
      } else {
        state.items.push({ ...newItem, quantity: 1 }); // add new with qty 1
      }
    },
    removeItem: (state, action) => {
      const removeItem = action.payload;
      const existingItem = state.items.find(
        (item) => item.card.info.id === removeItem.card.info.id
      );

      if (existingItem && existingItem.quantity > 1) {
        existingItem.quantity -= 1; // decrease qty
      } else {
        state.items = state.items.filter(
          (item) => item.card.info.id !== removeItem.card.info.id
        );
      }
    },
    clearCart: (state) => {
      state.items = [];
    },
  },
});

export const { addItem, removeItem, clearCart } = cartSlice.actions;
export default cartSlice.reducer;
