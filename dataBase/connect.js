import { mongoose } from "mongoose";
export default async function connect(){
    await mongoose.connect('mongodb+srv://admin:QuizApp_811@cluster0.nkqdyis.mongodb.net/?retryWrites=true&w=majority')
    console.log(" connected in dataBase")
}