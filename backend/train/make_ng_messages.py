"""Generates data/ng_messages.csv: Nigerian-style scam (label 1) and legitimate (label 0) messages.

This is SYNTHETIC data written by the team to cover Nigerian scam patterns that public datasets lack.
Each row has a `group` (the template it came from) so evaluation can hold out whole templates and
give an honest estimate instead of memorised near-duplicates.

To improve the model with REAL data: add rows to data/extra_messages.csv (text,label) - see README.
"""
import csv
import random
from pathlib import Path

random.seed(2026)
OUT = Path(__file__).resolve().parent.parent / "data" / "ng_messages.csv"

BANKS = ["GTBank", "Access Bank", "Zenith Bank", "First Bank", "UBA", "Fidelity Bank", "Stanbic IBTC", "Wema Bank",
         "Opay", "PalmPay", "Moniepoint", "Kuda", "Sterling Bank", "Union Bank", "Ecobank"]
TELCOS = ["MTN", "Glo", "Airtel", "9mobile"]
NAMES = ["Chinedu", "Aisha", "Tunde", "Ngozi", "Emeka", "Bola", "Ibrahim", "Funke", "Segun", "Amaka", "Kelechi",
         "Zainab", "Yusuf", "Chioma", "Dare", "Ifeanyi", "Hauwa", "Kunle", "Obinna", "Sade", "Tobi", "Binta"]
TLDS = ["xyz", "top", "click", "online", "site", "icu", "shop", "club", "live", "info", "co", "link", "cfd", "ng.com"]
KW = ["secure", "verify", "update", "login", "confirm", "kyc", "bvn", "unlock", "support", "online", "portal", "alert"]
LEGIT = ["gtbank.com", "jumia.com.ng", "mtnonline.com", "dhl.com", "cbn.gov.ng", "firstbanknigeria.com", "paystack.com",
         "zenithbank.com", "konga.com", "ikejaelectric.com", "accessbankplc.com", "ubagroup.com", "dstv.com", "google.com"]
SERVICES = ["Paystack", "Flutterwave", "Jumia", "Bolt", "Uber", "Netflix", "Spotify", "Google", "WhatsApp", "Opay", "Kuda"]


def phone():
    return "0" + random.choice(["803", "806", "813", "816", "703", "705", "810", "901", "902", "907", "812", "802", "708", "909"]) + "".join(random.choice("0123456789") for _ in range(7))


def acct():
    return "".join(random.choice("0123456789") for _ in range(10))


def money(lo=2, hi=900):
    n = random.choice([lo, 5, 10, 20, 25, 50, 100, 150, 200, 250, 500, hi]) * 1000
    return random.choice([f"N{n:,}", f"₦{n:,}", f"NGN {n:,}", f"N{n:,}.00", f"#{n:,}"])


def small_fee():
    return random.choice(["N2,500", "N5,000", "N7,500", "N10,000", "N15,000", "₦3,000", "₦20,000", "N1,500"])


def scam_url(brand=""):
    b = (brand or random.choice(BANKS)).lower().replace(" ", "")
    pat = random.choice([f"{b}-{random.choice(KW)}", f"{random.choice(KW)}-{b}", f"{b}{random.choice(KW)}", f"{b}-ng-{random.choice(KW)}", f"{random.choice(KW)}{b}{random.randint(1, 99)}"])
    scheme = random.choice(["http://", "https://", "", "http://", "www."])
    return f"{scheme}{pat}.{random.choice(TLDS)}" + random.choice(["", "", "/login", "/verify", f"/id={random.randint(1000, 99999)}", "/claim"])


def short_url():
    return random.choice(["bit.ly/", "tinyurl.com/", "cutt.ly/", "rb.gy/", "t.ly/", "is.gd/"]) + "".join(random.choice("abcdefghijklmnopqrstuvwxyz0123456789") for _ in range(random.randint(5, 7)))


def slots():
    b = random.choice(BANKS)
    return dict(bank=b, bank2=random.choice(BANKS), telco=random.choice(TELCOS), name=random.choice(NAMES), name2=random.choice(NAMES),
                amt=money(), amt2=money(), fee=small_fee(), phone=phone(), phone2=phone(), acct=acct(),
                surl=scam_url(b), surl2=scam_url(), short=short_url(), hrs=random.choice([1, 2, 3, 6, 12, 24, 48]),
                pct=random.choice([30, 40, 50, 60, 80, 100, 150, 200]), days=random.choice([3, 5, 7, 14, 30]),
                legit=random.choice(LEGIT), service=random.choice(SERVICES), code=str(random.randint(100000, 999999)),
                ref=str(random.randint(10000000, 99999999)), gb=random.choice([1.5, 2, 3.5, 5, 10, 20]),
                time=random.choice(["9am", "10am", "2pm", "4pm", "6pm"]), day=random.choice(["Monday", "Tuesday", "Friday", "Saturday", "Sunday", "tomorrow"]),
                n=random.randint(2, 40), usdsmall=random.choice(["$200", "$300", "$450", "$1,000", "N150,000", "N300,000"]), city=random.choice(["Dubai", "London", "Accra", "Istanbul", "Kuala Lumpur", "Lome"]), usd=random.choice(["$2.5 million", "$4.8m", "$10.5 million", "$750,000", "USD 3,200,000"]))


# ---------------------------------------------------------------- SCAM TEMPLATES (label 1)
SCAM = {
    "bank_block": [
        "URGENT: Dear customer, your {bank} account has been blocked. Verify your BVN and OTP immediately at {surl} to avoid suspension.",
        "{bank} Alert: Your account will be restricted within {hrs} hours. Click {surl} to update your details now.",
        "Dear {bank} customer, unusual activity detected on your account. Confirm your identity: {surl} or your account will be deactivated.",
        "Your {bank} account is LOCKED due to incomplete KYC. Re-activate here {surl} and enter your card PIN and OTP.",
        "SECURITY ALERT! {bank} has suspended your account. Login at {surl} to restore access immediately.",
        "{bank}: we noticed a login from a new device. If this was not you, verify now {short} else account goes dormant.",
        "Notice from {bank}: your debit card has been deactivated. Reply with your card number, expiry and CVV to reactivate.",
    ],
    "bvn_nin": [
        "CBN directive: all customers must link BVN and NIN before {days} days or accounts will be frozen. Update at {surl}",
        "Your BVN has been flagged. Send your BVN, date of birth and account number to {phone} to avoid account closure.",
        "FINAL NOTICE: NIN/BVN validation required by CBN. Failure to comply leads to restriction. Click {short} to validate.",
        "Dear user, {bank} is upgrading accounts. Provide your BVN and ATM PIN to the agent on {phone} to complete the upgrade.",
        "Federal Government BVN re-validation exercise. Register now {surl}. Deadline today.",
    ],
    "otp_forward": [
        "Hello, I mistakenly sent my verification code to your number. Please forward the 6 digit code you received, I am in a hurry.",
        "Please send me the code that was just sent to your phone so I can confirm your {bank} transfer reversal.",
        "We are reversing your {amt}. Reply with the OTP sent to you to complete the process.",
        "Hi, I used your number to register and the OTP came to you. Pls send it quick, it is urgent thanks.",
        "{bank} agent here. To cancel the unauthorised transaction, read out the 6 digit token you just received.",
    ],
    "callback_debit": [
        "Debit alert: {amt} transferred from your account to {name} {acct}. If not you, call {phone} immediately.",
        "{bank}: a transaction of {amt} has been initiated on your account. To stop it call our fraud desk on {phone} now.",
        "Your card was used for {amt} purchase at an unknown merchant. Dispute by calling {phone} or WhatsApp {phone2} immediately.",
        "ALERT: {amt} withdrawal pending approval. Reply STOP or call {phone} to cancel before it is processed.",
    ],
    "ponzi": [
        "Invest {amt} and receive {pct}% returns in {days} days! Guaranteed profit, no risk. Join our WhatsApp group {short}",
        "Double your money in 24 hours. Minimum investment N10,000. Over {n}00 people have been paid. Contact {phone} now.",
        "Crypto trading signals with guaranteed {pct}% weekly ROI. Our expert trader {name} manages your funds. Start with {amt} today.",
        "Make {amt} every week from home. Our forex mentorship is 100% guaranteed. Pay {fee} to join the VIP group.",
        "New investment platform paying daily returns of 10%. Withdraw anytime. Register at {surl} and deposit to get a bonus.",
        "Limited slots! Invest in our cooperative and earn {pct}% monthly. Referral bonus {amt}. Chat {phone} on WhatsApp.",
        "Mining pool opening. Deposit USDT and get double in {days} days. Smart contract guaranteed. {short}",
        "Don't miss this opportunity to become a millionaire. Our company pays {pct}% interest on every deposit. Call {phone}.",
    ],
    "advance_fee": [
        "Dear friend, I am Barrister {name}. You are the beneficiary of {usd} left by a late client. Contact me with your full name and phone to claim.",
        "Your fund of {usd} is ready for release but you must pay a clearance fee of {fee}. Send to account {acct} {bank}.",
        "CONGRATULATIONS! Your email was selected in the international lottery. You won {usd}. Pay processing fee {fee} to claim your prize.",
        "I am {name}, a bank manager. I have a business proposal worth {usd}. It is 100% risk free. Reply with your details urgently.",
        "Payment of {usd} has been approved in your favour by the Federal Government. Pay {fee} release fee to {acct} to receive it.",
        "Dear beneficiary, the UN has approved compensation of {usd} for scam victims. Send {fee} for delivery of your ATM card.",
    ],
    "telco_promo": [
        "{telco} Mega Promo! You have won {amt}. To claim, call {phone} and pay {fee} activation fee.",
        "Congratulations!!! Your number was selected as winner in the {telco} Anniversary Draw. Send your name and address to {phone} to claim your prize.",
        "You have been selected for a free {gb}GB data gift from {telco}. Click {surl} and enter your PIN to receive it.",
        "Lucky winner! You won a brand new car in the {telco} Reward Draw. Pay {fee} delivery fee to claim: {short}",
        "{telco} loyalty reward: {amt} credit waiting. Verify your number here {surl} within {hrs} hours.",
    ],
    "job_scam": [
        "Urgent recruitment! Earn {amt} weekly working from home. No experience needed. Pay {fee} registration fee to start. WhatsApp {phone}.",
        "You have been shortlisted for a job at {bank}. Pay {fee} for training and uniform to confirm your slot. Send to {acct}.",
        "Online job: like and share posts and earn {amt} daily. Registration fee {fee}. Message {phone} now.",
        "Oil company recruiting {n} staff. Salary {amt} monthly. Pay {fee} for medical and documentation. Limited slots.",
        "Congratulations, you got the job. To receive your appointment letter pay {fee} for verification to account {acct}.",
    ],
    "loan_scam": [
        "Instant loan up to {amt} with no collateral! Pay {fee} insurance fee first and get your money in 10 minutes. Apply {surl}",
        "Your loan of {amt} has been approved. Send {fee} to {acct} as processing fee to receive the funds today.",
        "Get {amt} loan without BVN. Contact {phone} on WhatsApp. Upfront fee {fee} required.",
        "Loan approved! Download the app {short}, allow access to your contacts and gallery to receive {amt}.",
    ],
    "advance_fee_more": [
        "Good day sir, I am a staff of a bank in {city}. A deceased customer left {usd} with no next of kin. I need a trustworthy partner to stand as next of kin and you will receive 30 percent.",
        "Compliments of the day. I represent an oil company and need an overseas partner to receive {usd}. Kindly reply for full details, this is confidential and legal.",
        "I am Mrs {name}, suffering from cancer, and want to donate {usd} to charity before I die. Please contact me and I will explain how you can receive it.",
        "Hello, I have {usd} to move out of the country and need a trustworthy person. You get 30 percent for your help. Reply if interested.",
        "Attention beneficiary, your over-due payment of {usd} is ready. Contact the director with your full name, address and phone number.",
    ],
    "romance_more": [
        "Hello I am stuck at {city} airport, my wallet and phone were stolen. Please send {usdsmall} I will pay you back tomorrow.",
        "My dear, I am traveling to meet you but customs is asking {fee} for my luggage. Please help me pay and I will refund you when I land.",
        "Honey I have a business emergency and need {usdsmall} today. You are the only person I trust. Please do not tell anyone.",
        "Hi dear, I am {name} from {city}. I saw your profile and I feel we are meant to be. I am rich but lonely. Please send me your WhatsApp number.",
    ],
    "romance": [
        "Hello dear, I am {name}, a US army officer on a peace mission. I have fallen in love with your profile. I need your help to send my funds home.",
        "My love, I am stranded at the airport and my card is blocked. Please send {amt} urgently, I will refund you tomorrow. Do not tell anyone.",
        "Hi beautiful, I am a widow with {usd} inheritance and no one to trust. Please be my partner and help me transfer it. Keep this secret.",
        "Baby I am in the hospital and need money for surgery. Please send {amt} to {acct} {bank}. I will pay you back, I promise.",
    ],
    "delivery": [
        "DHL: your parcel is held at customs. Pay {fee} delivery fee at {surl2} to release it. Package will be returned in {hrs} hours.",
        "Your package from abroad has arrived but a customs duty of {fee} is required. Pay now {short} or it will be destroyed.",
        "FedEx notice: failed delivery attempt. Reschedule and pay {fee} redelivery charge here: {surl2}",
        "Dear customer, your gift parcel from {name} is at the airport. Contact agent on {phone} and pay {fee} clearance.",
    ],
    "authority": [
        "EFCC notice: a warrant has been issued for your arrest over suspicious transactions. Call {phone} and pay {amt} to settle the matter.",
        "Nigeria Police Force: your account has been linked to fraud. To avoid prosecution, send {amt} bail fee to {acct}.",
        "This is {name} from the CBN fraud unit. Your account is under investigation. Do not tell anyone. Provide your BVN and PIN to clear your name.",
        "FIRS tax notice: you owe {amt} in unpaid tax. Pay within {hrs} hours at {surl} to avoid sanctions.",
        "Customs service: you have an unclaimed container in your name. Pay {fee} to release it. Call {phone}.",
        "Hello, this is your MD. I am in a meeting and cannot talk. I need you to buy {n} gift cards urgently and send me the codes. Keep it confidential.",
    ],
    "fake_vendor": [
        "Brand new iPhone 15 Pro Max at {amt}! Pay 50% deposit to {acct} {bank} and we deliver today. Limited stock, hurry. WhatsApp {phone}.",
        "Land for sale in Lekki, {pct}% discount this week only. Send {amt} deposit to {acct} to reserve. Papers will be sent after payment.",
        "Original items at half price! Pay first to {acct} {bank}, delivery in {days} days. No refund. Order via {phone}.",
        "Car for sale, owner travelling abroad, price slashed to {amt}. Pay the delivery fee {fee} first and the car will be shipped to you.",
        "Verified vendor. Pay full amount before delivery to {acct}. Trust me, I am a Christian. DM {phone} now before it is sold out.",
    ],
    "grant": [
        "FG empowerment grant of {amt} is open. Register at {surl} and pay {fee} processing fee to receive your money.",
        "CBN palliative: eligible Nigerians get {amt}. Click {short} and enter your BVN and bank details to claim.",
        "You qualify for the youth grant of {amt}. Send your name, BVN and {fee} to {acct} to be enrolled.",
        "Scholarship award! You have been selected for a full scholarship. Pay {fee} form fee to {acct} to secure your admission.",
    ],
    "whatsapp_hijack": [
        "Hi, please send me the 6 digit code WhatsApp just sent you. I sent it to your number by mistake.",
        "Your WhatsApp will expire today. Verify now {surl} to keep your account active.",
        "Check this out, you were mentioned in this video {short} (login with your WhatsApp number to view).",
    ],
    "crypto_airdrop": [
        "FREE AIRDROP! Connect your wallet at {surl} and claim {n}00 tokens before it ends. Limited to first 1000 users.",
        "Your wallet has been flagged. Validate it by entering your seed phrase at {surl} to avoid loss of funds.",
        "Elon is giving away 5000 BTC! Send 0.1 BTC to the address below and receive 0.2 BTC back instantly. Guaranteed.",
        "Support team: to recover your funds, share your 12-word recovery phrase with our agent on {phone}.",
    ],
    "utility": [
        "Your electricity meter will be disconnected today due to unpaid bill. Pay {fee} now via {surl} to avoid disconnection.",
        "DSTV: your subscription has expired and your decoder will be blocked. Renew here {short} and win {amt}.",
        "Your NIN registration is incomplete. SIM will be barred in {hrs} hours. Update at {surl}.",
        "Tax refund of {amt} is available. Claim it now by confirming your card details at {surl}.",
    ],
}

# ---------------------------------------------------------------- LEGITIMATE TEMPLATES (label 0)
HAM = {
    "bank_alert": [
        "Acct: {acct} Debit: NGN {n},500.00 Desc: POS purchase Bal: NGN {n}7,340.12 Date: 12-Nov-2026. Thank you for banking with {bank}.",
        "Credit alert: Your account has been credited with {amt} from {name} {name2}. Available balance {amt2}.",
        "{bank}: You have successfully transferred {amt} to {name} on {day}. Ref: {ref}.",
        "Transaction alert. Amt: {amt} Type: Airtime purchase. Your balance is {amt2}. If you did not authorise this, visit any {bank} branch.",
        "Your {bank} statement for October is ready. Log in to the official app to view it.",
        "Your card ending {code} was used at a merchant for {amt}. If this was you, no action is needed.",
    ],
    "security_warning": [
        "Never share your OTP, PIN or BVN with anyone. {bank} will never ask for your details by SMS, call or link.",
        "Fraud alert from {bank}: beware of fake calls. We do not request your password, card PIN or OTP. Report suspicious messages in the app.",
        "Stay safe: do not click links in unsolicited messages. Always use the official {bank} app or website.",
        "Reminder: your {bank} token is for your use only. Do not disclose it to anyone, including bank staff.",
        "Scam awareness: Fraudsters pretend to be bank staff. Hang up and call the number at the back of your card.",
    ],
    "otp_legit": [
        "Your {service} verification code is {code}. It expires in 10 minutes. Do not share this code with anyone.",
        "{code} is your {service} login code. If you did not request it, ignore this message.",
        "Use {code} to confirm your {bank} transaction of {amt}. Never share this OTP.",
        "Your one-time password is {code}. Valid for 5 minutes. {service} will never call to ask for it.",
    ],
    "orders": [
        "Your {service} order #{ref} has been dispatched and will arrive on {day}. Track it at {legit}.",
        "Hi {name}, thanks for shopping with us. Your receipt for {amt} is attached. Delivery in {days} days.",
        "Your DHL shipment {ref} is out for delivery today. No payment is required. Track on dhl.com.",
        "Order confirmed: 1 x Samsung phone charger, {amt}. Pay on delivery when the rider arrives.",
        "Your ride with {service} is arriving in {n} minutes. Driver: {name}, plate number KJA {n}2 AB.",
    ],
    "telco_info": [
        "You have {gb}GB data left. It expires on 30 Nov. Dial *131# to check your balance.",
        "{telco}: Your airtime recharge of N500 was successful. Your new balance is N{n}50. Thank you.",
        "Your data plan has been renewed successfully. Enjoy your {gb}GB. Dial *312# for more offers.",
        "Your electricity token purchase was successful. Token: {ref}. Units: {n}.4 kWh. Amount {amt}.",
        "{telco} reminder: your subscription renews on {day}. Dial *141# to manage it.",
    ],
    "chat": [
        "How far? I dey come, make we meet for the junction by {time}.",
        "Mummy I will be home late today, there is traffic on the bridge. Don't wait up.",
        "Don't forget the meeting on {day} by {time}. Please bring the printed documents.",
        "Hello {name}, are you coming for church service on Sunday? The program starts at 9am.",
        "Thanks for the update. I will review the report tonight and send my feedback tomorrow morning.",
        "Abeg, send me the address of the restaurant. I am on my way and I will be there in {n} minutes.",
        "Happy birthday {name}! Wishing you a wonderful year ahead. God bless you.",
        "Did you watch the match last night? That second half was crazy, I cannot believe the referee.",
        "Please find attached the invoice for March. Kindly confirm receipt and let me know if you have any questions.",
        "Reminder: your dental appointment is on {day} at {time}. Reply C to confirm or call the clinic to reschedule.",
        "I just reached home. Dinner is ready, the rice is in the pot. Call me when you are free.",
        "Our class holds {day} at {time} in the main hall. Lecturer says attendance is compulsory.",
        "I sent the money for the rent to the landlord yesterday. He confirmed that he received it.",
        "Good morning sir, I have submitted the assignment on the portal. Please check and confirm.",
        "Wetin dey happen? You never reply my message since morning. Everything dey alright?",
        "The package you ordered from the market is ready. I will bring it to your office on {day}.",
    ],
    "work": [
        "Team, standup is moved to {time}. Please update the tracker before then.",
        "Your salary for this month has been paid. Please check your account. HR.",
        "Hi {name}, the client approved the proposal. Let us schedule the kick-off meeting for {day}.",
        "Please remember to submit your timesheet by Friday. Thanks, Admin.",
        "The server maintenance is scheduled for Saturday midnight. Expect short downtime.",
    ],
    "legit_links": [
        "Track your parcel at https://www.dhl.com/ng-en/home/tracking.html using reference {ref}.",
        "Your statement is available on the official {bank} app. For help visit https://www.{legit}.",
        "Thanks for registering. Verify your email by logging into https://{legit} using your own password.",
        "Check the exam timetable on the school portal https://{legit}. Good luck.",
    ],
}


HAM.update({
    "promo_legit": [
        "{telco}: Get {gb}GB for N{n}00 valid for 30 days. Dial *312# to subscribe. T&Cs apply.",
        "Enjoy double data this weekend on selected plans. Visit the {telco} app to see offers.",
        "Thank you for being a {telco} customer. Your next bill is due on {day}. Pay in the app or at any outlet.",
        "{bank} is closed on Monday for the public holiday. Our digital channels remain available 24/7.",
        "Our new branch is now open in Ikeja. Visit us Monday to Friday, 8am to 4pm. {bank}.",
    ],
    "community": [
        "Reminder: the residents' meeting is on {day} by {time} at the community hall. Please come on time.",
        "Brethren, the midweek service holds {day} by {time}. Come with your Bible and a friend.",
        "Parents, school resumes on Monday. Please ensure your children are in complete uniform.",
        "The match is on Saturday at the stadium. {name} has the tickets, we will meet at the gate by {time}.",
        "Our family meeting is {day} at {time}. Please confirm if you are coming so we can plan food.",
        "Congratulations {name} on your graduation! We are so proud of you. See you at the party.",
        "Good evening ma, I have delivered the items to your house. Please confirm you received them.",
        "Can you help me pick up the kids from school today? I have a meeting that will run late.",
    ],
    "service_msgs": [
        "Your appointment with Dr {name} is confirmed for {day} at {time}. Please arrive 15 minutes early.",
        "Your flight to Abuja departs at {time} on {day}. Check in at least 2 hours before departure.",
        "Hi {name}, your food order is on its way. The rider will call you when he arrives.",
        "Your password was changed successfully. If this was not you, please contact support through the official app.",
        "Welcome to {service}! Your account has been created. Explore the app to get started.",
        "Your bill of {amt} for this month has been generated. You can pay through the official app or website.",
        "Your package has been delivered to the front desk. Please collect it with your ID.",
        "Exam results are out. Log into the student portal with your matric number to check your results.",
    ],
    "work_more": [
        "Hi {name}, can we move the call to {time}? I have a conflict at the earlier slot.",
        "Please review the attached contract and send your comments by {day}. Thanks.",
        "The quarterly report is ready. I have shared the link on our company drive.",
        "Reminder to all staff: the fire drill takes place {day} by {time}. Assemble at the car park.",
        "Interview scheduled for {day} at {time} at our Lagos office. Please bring your CV and ID. There is no fee for any stage of our hiring process.",
        "Your leave request has been approved. Enjoy your time off.",
    ],
    "p2p_money": [
        "Hi {name}, I just sent {amt} to your account for the fabric. Please confirm when you get it.",
        "Thanks for the transfer of {amt}, I have received it. God bless you.",
        "I will send the money for the tickets on {day}. Abeg give me till evening.",
        "Your {bank} account has been credited with {amt}. Available balance: {amt2}. Thank you for banking with us.",
        "Dear customer, your account has been credited with {amt} from {name}. Balance {amt2}.",
        "Dear customer, your transfer of {amt} to {name} was successful. Ref {ref}.",
        "Dear {name}, your salary of {amt} has been credited. Happy new month.",
        "Please remember to pay the electricity bill before {day}. The meter is almost out of units.",
    ],
    "chat_more": [
        "Omo, that jollof at the party was something else. We must go again next week.",
        "I no go fit come today, I dey sick small. I go call you tomorrow.",
        "Dad says he will pick you up from the airport. Flight lands at {time}.",
        "Thanks for the gift, it was so thoughtful. God bless you abundantly.",
        "Please remind {name} to bring the keys when coming. I will not be at home till evening.",
        "Did you get my email about the project? Let me know if you need anything else from me.",
        "Sorry I missed your call, I was in a meeting. I will call you back in {n} minutes.",
        "What time are you free this weekend? We can finally catch up over lunch.",
    ],
})

PREFIX = ["", "", "", "", "URGENT: ", "ALERT! ", "Notice: ", "Dear customer, ", "Hello, ", "Attention: ", "Hi {name}, ", "Dear {name}, "]
SUFFIX = ["", "", "", "", " Thank you.", " Act now!", " Reply now.", " God bless.", " Do not ignore.", " Regards."]


def noisy(text, p_scam):
    if random.random() < 0.12:
        text = text.upper() if random.random() < 0.3 else text.lower()
    if random.random() < 0.15:
        text = text.replace(".", "").replace(",", "")
    if random.random() < 0.08:
        text = text.replace("you", "u").replace("Please", "Pls").replace("please", "pls")
    if random.random() < 0.06:
        text += " " + random.choice(["🙏", "🔥", "💰", "✅", "🚨", "😊"])
    return text.strip()


def build(families, label, per_template):
    rows = []
    for fam, templates in families.items():
        for i, t in enumerate(templates):
            seen = set()
            for _ in range(per_template):
                s = slots()
                txt = t.format(**s)
                if label == 1 and random.random() < 0.5:
                    txt = random.choice(PREFIX).format(**s) + txt + random.choice(SUFFIX)
                elif label == 0 and random.random() < 0.35:
                    txt = random.choice(PREFIX[3:]).format(**s) + txt
                txt = noisy(txt, label)
                if txt in seen:
                    continue
                seen.add(txt)
                rows.append((txt, label, f"{'S' if label else 'H'}:{fam}-{i}"))
    return rows


def main():
    rows = build(SCAM, 1, 14) + build(HAM, 0, 30)
    random.shuffle(rows)
    with open(OUT, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["text", "label", "group"])
        w.writerows(rows)
    pos = sum(r[1] for r in rows)
    print(f"wrote {len(rows)} rows ({pos} scam / {len(rows) - pos} legitimate) -> {OUT}")


if __name__ == "__main__":
    main()
