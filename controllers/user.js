import { asyncHandler } from "../utils/asyncHandler.js"
import { ApiError } from "../utils/apiError.js"
import { User } from "../models/user.js"
import {uploadOnCloudinary} from "../utils/cloudinary.js"
import {ApiResponse} from "../utils/apiResponse.js"

const registerUser = asyncHandler(async (req, res) => {
    // get user details from frontend

    const {fullName, email, username, password} = req.body
    // console.log(req.body);
    
    // validation of request

    if (
        [fullName, email, username, password].some((field) => field?.trim() === "")
    ) {
        throw new ApiError(400, "All fields are required")
    }
    // check if user exists

    const existingUser = await User.findOne({
        $or: [{ username }, { email }]
    })
    
    if(existingUser) {
        throw new ApiError(409, "The user already exists")
    }

    // check for images and avatar

    const avatarLocalPath = req.files?.avatar[0]?.path;
    // const coverImageLocalPath = req.files?.coverImage[0]?.path;

    let coverImageLocalPath;
    if(req.files && Array.isArray(req.files.coverImage) && req.files.coverImage.length > 0){
        coverImageLocalPath = req.files.coverImage[0].path
    }

    if(!avatarLocalPath){
        throw new ApiError(400, "Avatar file is required!")
    }

    // console.log(req.files);

    // upload them to cloudinary
    const avatar = await uploadOnCloudinary(avatarLocalPath)
    const coverImage = await uploadOnCloudinary(coverImageLocalPath)

    if (!avatar) {
        throw new ApiError(400, "Avatar file is required")
    }
    // create user object - create entry into mongo

    const user = await User.create({
        fullName,
        avatar: avatar.url,
        coverImage: coverImage?.url || "",
        email,
        password,
        username: username.toLowerCase()
    })

    // remove password and refresh token field from the response

    const createdUser = await User.findById(user._id).select(
        "-password -refreshToken"
    )

    // check for user creation
    
    if(!createdUser) {
        throw new ApiError(500, "Something went wrong while registering the user")
    }

    // return res
    return res.status(201).json(
        new ApiResponse(200, createdUser, "user registered successfully!")
    )
})

const loginUser = asyncHandler(async (req, res) => {
    // take off data from req body
    const {email, username, password} = req.body

    if(!username || !email) {
        throw new ApiError(400, "Username or Email required")
    }
    // Find the user in db

    const user = await User.findOne({
        $or: [{username}, {email}]
    })

    if(!user) {
        throw new ApiError(404, "User does not exist") 
    }

    const isPassValid = await user.isPassCorrect(password)

    if(!isPassValid) {
        throw new ApiError(401, "Invalid User credentials") 
    }

    // provide user a refresh token after each periodic interval

    const generateAccessAndRefreshTokens = async (userId) => {
        try {
            const user = await User.findById(userId)
            const accessToken = user.generateAccessToken()
            const refreshToken = user.generateRefreshToken()

            user.refreshToken = refreshToken
            await user.save({validateBeforeSave : false})

            return { accessToken, refreshToken }            
        } catch (error) {
            throw new ApiError(500, "Something went wrong while generating refresh and access tokens")
        }
    }

    // check for the access token 
    // match the hashed password in db

    const {accessToken, refreshToken} = await generateAccessAndRefreshTokens(user._id)

    // send cookies of tokens

    const loggedInUser = await User.findById(user._id).select("-password -refreshToken")

    const options = {
        httpOnly: true,
        secure : true,
    }

    // Allow user to access the file uploading i.e. authorization required procedure

    return res
    .status(200)
    .cookie("accessToken", accessToken, options)
    .cookie("refreshToken", refreshToken, options)
    .json(
        new ApiResponse(
            200,
            {
                user: loggedInUser, accessToken, refreshToken
            },
            "User logged In Successfully !"
        )
    )
})

const logoutUser = asyncHandler(async (req, res) => {
    // auth middleware has provided us req.user
    await User.findByIdAndUpdate(
        req.user._id,
        {
            $set: {
                refreshToken: undefined
            }
        },
        {
            new: true
        }
    )

    const options = {
        httpOnly: true,
        secure : true,
    }

    return res
    .status(200)
    .clearCookie("accessToken", options)
    .clearCookie("refreshToken", options)
    .json(new ApiResponse(200, {}, "User Logged out successfully"))
})

export {
    registerUser,
    loginUser,
    logoutUser
}