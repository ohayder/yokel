1. In the createUserHandler function (account.go):
This TODO indicates that the email sending functionality for the finalization token needs to be implemented. Currently, the token is just returned in the response for testing purposes.


2. In the finalizeUserHandler function (account.go):

This TODO indicates that the validation of the finalization token needs to be implemented. Currently, this step is stubbed out and not actually performing any validation.
These TODOs represent important security features that need to be implemented:

1. Email Sending: Implementing secure email sending for the finalization token is crucial for the user creation process. This ensures that only users with access to the specified email can finalize their account creation.
Token Validation: Properly validating the finalization token is essential to ensure that only legitimate account creation attempts are processed.
To complete these tasks:
For email sending:
Implement an email sending service (using a library like gomail or directly using the net/smtp package).
Create an email template for the finalization token.
Securely generate and store the finalization token, associating it with the user's email and username.
Send the email with the finalization token instead of returning it in the response.

2. For token validation:
Implement a secure method to store the generated finalization tokens (e.g., in the database with an expiration time).
In the finalizeUserHandler, retrieve the stored token for the given username and validate it against the provided token.
Implement proper error handling for invalid or expired tokens.
These implementations will significantly enhance the security and functionality of the user creation and finalization process.




- Implement an interface that "wraps" gomail for the sake of sending emails. We intrerface this so we can test it with a mock object later (don't mock it now, just do it later)
- Update the yokel.yaml file to include the email settings (smtp server, port, etc)
- Create necessary structs to hold magic link information that we send out, mapping it to an email address (that is not yet a user - don't store in DB)
- Update the finalizeUserHandler to validate a magic link sent to the user's email address, when it ssubmitted to finalizeUserHandler. It should check the structure you've made to map the email to the magic link and ensure that the magic link is valid, and that the token hasn't expired. If it is valid, then we can finalize the user creation process, and create the user in the database (as-per ABOUT.md)


