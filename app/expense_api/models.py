from pydantic import BaseModel, PositiveInt, Field
from typing import Annotated

from app.validators import ValidPeriod

Day = Annotated[int, Field(None, ge=1, le=31, description="Day of month (1-31)")]
Month = Annotated[int, Field(None,ge=1,le=12, description="Month (1-12)")]
Year = Annotated[int, Field(None, ge=2025, le=2030,description="Year (2000-2100). Required if day or month is provided.",)]

class ExpenseCreate(BaseModel):
    amount: PositiveInt
    category: str
    payment_method: str
    description: str | None = None
    
class MonthlyAvgQuery(BaseModel):
    month: Month
    year: Year
    
class TransactionSummaryQuery(BaseModel):
    day:Day
    month:Month
    year:Year

class ReportCreate(BaseModel):
    period: ValidPeriod

