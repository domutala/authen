/** Source de temps injectable : rend les services testables (expiration, TTL...). */
export interface Clock {
  now(): Date;
}
