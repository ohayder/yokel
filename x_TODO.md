# TODO:

## Testing 

After I thought the code was done I had Claude3.5 Sonnet and o1 review the code multiple times for accuracy against the API document and vice versa. I'm pretty confident that it matches the API document.

I had them both walk through the code to generate TEST.md which lists the API.md endpoint, and their corresponding functions in the codebase, as-well-as every possible error the endpoint could return for the given function.

For testing we now need to make a test to ensure we derive every possible error case for every endpoint.

I want to see how well the AI does unit testing with this find of test cases, so I think I will have them generate it in chunks and test it out.

# POST-Test checks 

- ARE ALL REQUIRED HEADERS PRESENT IN EVERY REQUEST
- ARE ALL REQUIRED VALUES PRESENT IN EVERY REQUEST
- IS ALL USERNAME/PASSWORD input VALIDATED and sanitized
- IS ALL OTHER INPUT VALIDATED
    - voucher lifetimes, times, dates, etc.
- ARE ALL RESPONSES VALIDATED and sanitized
    - I should never, ever, allow ANY input to be echoed back in any part of a response

## Better Logging

I want "slog" and the ability to up the levels at runtime

## Documentation

Make a bot run around and do the docs 

## SMTP Test flag

I want a --test-smtp flag that will send an email to the given address for testing purposes; validating the user's yokel yaml file.

## OS Environment Variables

- Admin account should be able to be set with an environment variable so I don't have to keep resetting it

## Password Resets

- Endpoint to re-sent magic link email, and force the user to login and change their password




# Security Audit

- Neeed reviews to check that I didn't bonk something silly