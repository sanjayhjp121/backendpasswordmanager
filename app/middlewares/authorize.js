function authorize(role) {
    // console.log("Authorize called")
    return (req, res, next) => {
        if (req.user.role === role) {
            next();
        } else {
            res.status(403).json({ message: 'You not have access for this' });
        }
    };
}

module.exports = authorize;
