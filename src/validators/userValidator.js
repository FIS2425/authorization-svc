import { z } from 'zod';

export const userValidator = z.object({
  email: z
    .string({ required_error: 'Email is required' })
    .email('Invalid email address'),
  password: z
    .string({ required_error: 'Password is required' })
    .min(8, 'Password must be at least 8 characters long')
    .max(32, 'Password must be at most 32 characters long')
    .regex(
      /^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[!@#$%^&*()_+\-=[\]{};':"\\|,.<>/?])/,
      'Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character'
    )
    .refine((password) => {
      return !/\s/.test(password);
    }, 'Password must not contain spaces'),
  roles: z
    .string({ required_error: 'Roles are required' })
    .array(z.string())
    .refine(
      (roles) =>
        roles.length > 0,
      {
        message: 'At least one role is required.',
      }
    )
    .refine(
      (roles) =>
        roles.every((role) =>
          ['admin', 'clinicadmin', 'doctor', 'patient'].includes(role)
        ),
      {
        message: 'Invalid role found.',
      }
    )
    .default(['patient']),
  doctorid: z.string().optional(),
  patientid: z.string().optional(),
});

export const userEditValidator = z.object({
  email: z
    .string()
    .email('Invalid email address')
    .optional(),
  password: z
    .string()
    .min(8, 'Password must be at least 8 characters long')
    .max(32, 'Password must be at most 32 characters long')
    .regex(
      /^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[!@#$%^&*()_+\-=[\]{};':"\\|,.<>/?])/,
      'Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character'
    )
    .refine((password) => {
      return !/\s/.test(password);
    }, 'Password must not contain spaces')
    .optional(),
  roles: z
    .string()
    .array(z.string())
    .refine(
      (roles) =>
        roles.length > 0,
      {
        message: 'At least one role is required.',
      }
    )
    .refine(
      (roles) =>
        roles.every((role) =>
          ['admin', 'clinicadmin', 'doctor', 'patient'].includes(role)
        ),
      {
        message: 'Invalid role found.',
      }
    )
    .optional(),
  doctorid: z.string().optional(),
  patientid: z.string().optional(),
});

export const userLoginValidator = z.object({
  email: z
    .string({ required_error: 'Email is required' })
    .email('Invalid email address'),
  password: z.string({ required_error: 'Password is required' }),
});
