import mongoose from "mongoose";

const subscriptionSchema = new mongoose.Schema({
    subscriber:{
        type : mongoose.Schema.Types.ObjectId, // one whos is subscribing
        ref: "User"
    }, 
    channel:{
        type: mongoose.Schema.Types.ObjectId, // one to whom 'Subscriber' subscribed
        ref:"User"
    }
}, {timestamps: true})

export const Subscription = mongoose.model("Subscription", subscriptionSchema)