from balethon import Client
from balethon.conditions import document, private, text, video
from balethon.objects import InlineKeyboard, ReplyKeyboard
from gradio_client import Client as C
import asyncio
import aiohttp

client_hf = C("rayesh/process_miniapp")
bot = Client("1261816176:T4jSrvlJiCfdV5UzUkpywN2HFrzef1IZJs5URAkz")

user_states = {}
user_parametrs_sub = {}
user_parametrs_dub = {}

home_keyboard = ReplyKeyboard(["خانه"])

@bot.on_message(text)
async def answer_message(message):
    user_id = message.author.id
    state = user_states.get(user_id)
    
    if message.text in ("خانه", "/start"):
        user_states[user_id] = ['awaiting_choose']
        await message.reply(
            """🎉 یه خبر خفن برای تولیدکننده‌های محتوا!
دیگه نگران ترجمه و دوبله ویدیوهای انگلیسی نباشید! 🎙✨
ربات "شهر فرنگ" همه کارو براتون انجام می‌ده:
✅  زیرنویس فارسی سریع و دقیق
✅ قابلیت شخصی سازی زیرنویس و ترجمه
✅ صرفه‌جویی در زمان و هزینه

دیگه وقتشه محتوای جهانی تولید کنی! 🚀🔥
🔗 همین حالا امتحان کن!""",
            reply_markup=InlineKeyboard([
                [("تولید زیرنویس 📜 ", "sub")],
                [("دوبله فارسی(در حال توسعه) 🎬 ", "a")],
                [(" توضیحات بیشتر 📖 ", "toturial")]
            ])
        )

@bot.on_callback_query()
async def handle_callbacks(callback_query):
    user_id = callback_query.author.id
    if user_id not in user_states:
        await bot.send_message(
            chat_id=callback_query.message.chat.id,
            text="لطفا ابتدا فرمان /start را ارسال کنید."
        )
        return

    state = user_states[user_id][0]
    
    if state == 'awaiting_choose':
        if callback_query.data == "toturial":
            await bot.send_message(
                chat_id=callback_query.message.chat.id,
                text="""🎬 راهنمای سریع "شهر فرنگ"!

🔹 مرحله ۱: انتخاب نوع تبدیل
🎙 دوبله فارسی(در حال توسعه) یا 📜 زیرنویس فارسی؟

🔹 مرحله ۲: سریع یا پیشرفته؟
⚡️ سریع (بی‌دردسر و فوری)
⚙️ پیشرفته (شخصی‌سازی بیشتر)

🔹 مرحله ۳: آپلود ویدیو
⏳ کمی صبر کن تا هوش مصنوعی جادو کنه! ✨""",
                reply_markup=InlineKeyboard([
                    [("تولید زیرنویس ", "sub")]
                ])
            )
        elif callback_query.data == "sub":
            user_states[user_id] = ["awaiting_parametrs", "sub"]
            await bot.send_message(
                chat_id=callback_query.message.chat.id,
                text="لطفا یک گزینه را از کیبورد انتخاب کنید.",
                reply_markup=InlineKeyboard([
                    [("تولید زیرنویس سریع ⚡️", "sub_def")],
                    [("(به زودی)تولید زیرنویس پیشرفته ⚙️", "sub_custome")]
                ])
            )

    elif state == 'awaiting_parametrs':
        if callback_query.data == "sub_custome":
            user_states[user_id][0] = 'awaiting_send_parametrs'
            await bot.send_message(
                chat_id=callback_query.message.chat.id,
                text=" رنگ زیرنویس رو انتخاب کن 🧐.",
                reply_markup=InlineKeyboard([
                    [(" ⚪️ سفید", "white")],
                    [(" ⚫️ سیاه", "black")],
                    [(" 🟡 زرد", "yellow")]
                ])
            )
        elif callback_query.data == "sub_def":
            user_states[user_id][0] = 'awaiting_document'
            user_parametrs_sub[user_id] = ['yellow', 'arial']

    elif state == 'awaiting_send_parametrs':
        if callback_query.data in ("white", "black", "yellow"):
            user_parametrs_sub[user_id] = [callback_query.data]
            user_states[user_id][0] = 'awaiting_font'
            await bot.send_message(
                chat_id=callback_query.message.chat.id,
                text="فونت مورد نظر را انتخاب کنید 📑",
                reply_markup=InlineKeyboard([
                    [("ب نازنین", "nazanin")],
                    [("ب یکان", "yekan")],
                    [("آریا", "arial")]
                ])
            )

    elif state == 'awaiting_font':
        if callback_query.data in ("nazanin", "yekan", "arial"):
            user_parametrs_sub[user_id].append(callback_query.data)
            user_states[user_id][0] = 'awaiting_document'
            await bot.send_message(
                chat_id=callback_query.message.chat.id,
                text="لطفا ویدیو انگلیسی مورد نظر خود را آپلود کنید"
            )

@bot.on_message(video)
async def handle_document(message):
    user_id = message.author.id
    if message.video.duration > 300:
        await message.reply("❌ لطفا ویدئوی زیر ۵ دقیقه ارسال کنید")
        user_states[user_id] = ['awaiting_choose']
        return

    downloading = await message.reply("در صف پردازش . . . 💡")
    
    try:
        file = await bot.get_file(message.video.id)
        file_path = file.path
        video_url = f"https://tapi.bale.ai/file/bot1261816176:T4jSrvlJiCfdV5UzUkpywN2HFrzef1IZJs5URAkz/{file_path}"
        
        job = client_hf.submit(
            url=video_url,
            clip_type=user_states[user_id][1],
            parameters=user_parametrs_sub.get(user_id, []),
            api_name="/main",
        )

        final_video = None
        while not job.done():
            await asyncio.sleep(1)
            if job.outputs():
                final_video = job.outputs()[0]
                break

        if final_video:
            await bot.send_video(
                chat_id=message.chat.id,
                video=final_video["video"],
                caption="🎭 شهر فرنگه، از همه رنگه!✨ پردازش ویدیوی شما تموم شد! ✨"
            )
            await bot.send_message(
                chat_id=message.chat.id,
                text="برای ادامه، یک گزینه را انتخاب کنید:",
                reply_markup=InlineKeyboard([
                    [("تولید زیرنویس 📜 ", "sub")]
                ])
            )
        user_states[user_id] = ['awaiting_choose']

    except Exception as e:
        await downloading.edit_text(f"❌ خطا در پردازش: {str(e)}")
        user_states[user_id] = ['awaiting_choose']
        await bot.send_message(
            chat_id=message.chat.id,
            text="برای ادامه، یک گزینه را انتخاب کنید:",
            reply_markup=InlineKeyboard([
                [("تولید زیرنویس 📜 ", "sub")]
            ])
        )

bot.run()
            
