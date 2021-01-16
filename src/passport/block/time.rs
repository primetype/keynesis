use std::{
    convert::TryFrom,
    fmt::{self, Debug, Display, Formatter},
    ops::Deref,
    str::FromStr,
    time::SystemTime,
};

#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub struct Time(u32);

impl Time {
    /// number of seconds since UNIX_EPOCH for the COVID era
    ///
    /// this is the starting point in time. It allows up to compare
    /// against a smaller number and to have a smaller Time (32bits)
    /// in order to reach to valid data in the Passport era.
    ///
    ///
    pub const COVID_EPOCH: u64 = 1577836800;

    /// size of the `Time`
    ///
    /// ```
    /// # use keynesis::passport::block::Time;
    /// assert_eq!(Time::SIZE, 4);
    /// ```
    pub const SIZE: usize = std::mem::size_of::<Self>();

    /// get the current timestamp from the local system
    ///
    /// if the function is used outside of normal usage (i.e.
    /// if the local time is before UNIX_EPOCH) then the function
    /// has undefined behavior.
    pub fn now() -> Self {
        let now = SystemTime::now();
        let since_epoch = if let Ok(d) = now.duration_since(SystemTime::UNIX_EPOCH) {
            d.as_secs() - Self::COVID_EPOCH
        } else {
            // this is impossible because the `SystemTime` is taken as `now` and
            // unless the users are playing silly with the local date and time
            // this is completely unreachable as the `now.duration_since(1/1/2020)`
            // will always successfully return something
            unsafe { std::hint::unreachable_unchecked() }
        };

        if let Ok(time) = u32::try_from(since_epoch).map(Self) {
            time
        } else {
            // this is something that may happen if we reach year 2156
            unsafe { std::hint::unreachable_unchecked() }
        }
    }

    /// get the SystemTime out of this given time.
    ///
    /// `Time` represents the keynesis' passport's time in seconds since
    /// COVID era. This function convert the time from this referential to
    /// the system time (since UNIX Epoch).
    pub fn to_system_time(self) -> SystemTime {
        let d = std::time::Duration::from_secs(self.seconds_since_unix_epoch());
        SystemTime::UNIX_EPOCH.checked_add(d).unwrap()
    }

    /// get the number of seconds elapsed since 01/01/2020
    ///
    /// Time is counted since Covid ERA. I.E, all time is counted in seconds since
    /// 1st January 2020, 00h00m00s UTC. This function returns the number of seconds
    /// since that time.
    pub fn seconds_since_covid_epoch(self) -> u32 {
        self.0
    }

    /// number of seconds since unix epoch
    pub fn seconds_since_unix_epoch(self) -> u64 {
        self.0 as u64 + Self::COVID_EPOCH
    }
}

impl Display for Time {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        Display::fmt(&self.0, f)
    }
}

impl FromStr for Time {
    type Err = <u32 as FromStr>::Err;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        s.parse().map(Self)
    }
}

impl<'a> TryFrom<&'a str> for Time {
    type Error = <Self as FromStr>::Err;
    fn try_from(value: &'a str) -> Result<Self, Self::Error> {
        Self::from_str(value)
    }
}

impl From<Time> for u32 {
    fn from(time: Time) -> Self {
        time.0
    }
}

impl From<u32> for Time {
    fn from(time: u32) -> Self {
        Self(time)
    }
}

impl Deref for Time {
    type Target = u32;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::prelude::*;
    use quickcheck::{Arbitrary, Gen};

    impl Arbitrary for Time {
        fn arbitrary(g: &mut Gen) -> Self {
            Self(u32::arbitrary(g))
        }
    }

    #[quickcheck]
    fn to_string_from_str(time: Time) -> bool {
        let s = time.to_string();
        let d = Time::from_str(&s).expect("Time should be decoded properly");

        d == time
    }

    /// test that the covid epoch time starts on the 01/01/2020 at 00:00:00 UTC
    ///
    #[test]
    fn covid_epoch() {
        const COVID_EPOCH: Time = Time(0);

        let system_time = COVID_EPOCH.to_system_time();
        let elapsed = system_time
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("always valid");
        assert_eq!(elapsed.as_secs(), Time::COVID_EPOCH);

        let date = DateTime::<Utc>::try_from(system_time).unwrap();
        assert_eq!(date.year(), 2020);
        assert_eq!(date.month(), 1);
        assert_eq!(date.day(), 1);
        assert_eq!(date.hour(), 0);
        assert_eq!(date.minute(), 0);
        assert_eq!(date.second(), 0);
    }
}
