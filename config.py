status_map = {
    0: 'Не вказано',
    1: 'На зберіганні (порожній)',
    2: 'Відправлено в користування',
    3: 'Відправлено на заправку',
    4: 'Непридатний (списаний)',
    5: 'Одноразовий (фарба у банці)',
    6: 'На зберіганні (заправлений)'
}

from datetime import datetime, timedelta


def human_readable_date(date_str):
    # Парсимо вхідну дату
    try:
        # Спробуємо формат "дд.мм.рррр, гг:хх:сс"
        input_date = datetime.strptime(date_str, "%d.%m.%Y, %H:%M:%S")
    except ValueError:
        try:
            # Спробуємо формат "рррр-мм-дд гг:хх:сс.мікросекунди"
            input_date = datetime.strptime(date_str, "%Y-%m-%d %H:%M:%S.%f")
        except ValueError:
            return "Невірний формат дати"

    now = datetime.now()
    diff = now - input_date

    # Секунди, хвилини, години, дні
    seconds = diff.total_seconds()
    minutes = seconds // 60
    hours = minutes // 60
    days = diff.days

    # Якщо це сьогодні
    if days == 0:
        if hours < 1:
            if minutes < 1:
                return "Щойно"
            elif minutes == 1:
                return "Хвилину тому"
            else:
                return f"{int(minutes)} хвилин тому"
        elif hours == 1:
            return "Годину тому"
        else:
            return f"{int(hours)} годин тому"

    # Якщо це вчора
    elif days == 1:
        return "Вчора"

    # Якщо це тиждень тому або менше
    elif days < 7:
        return f"{days} {'день' if days == 1 else 'дні' if days in [2, 3, 4] else 'днів'} тому"

    # Якщо це місяць тому або менше
    elif days < 30:
        weeks = days // 7
        return f"{weeks} {'тиждень' if weeks == 1 else 'тижні' if weeks in [2, 3, 4] else 'тижнів'} тому"

    # Якщо більше місяця
    else:
        months = days // 30
        if months < 12:
            return f"{months} {'місяць' if months == 1 else 'місяці' if months in [2, 3, 4] else 'місяців'} тому"
        else:
            years = months // 12
            return f"{years} {'рік' if years == 1 else 'роки' if years in [2, 3, 4] else 'років'} тому"